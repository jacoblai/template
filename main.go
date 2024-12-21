package main

import (
	"T-Mind_/mschema"
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"golang.org/x/sys/unix"
)

// Config 应用配置
type Config struct {
	MongoURI     string
	DatabaseName string
	JWTSecret    string
	Port         string
}

// App 应用程序结构
type App struct {
	config     *Config
	db         *mongo.Database
	httpServer *http.Server
}

// Response API响应结构
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Claims JWT认证信息
type Claims struct {
	UserID       string `json:"userId"`
	EnterpriseID string `json:"enterpriseId"`
	jwt.RegisteredClaims
}

// NewApp 创建应用实例
func NewApp(config *Config) *App {
	return &App{
		config: config,
	}
}

// 使用schema生成MongoDB验证规则
func GetUserValidator() *mschema.Schema {
	return mschema.Reflect(&User{})
}

// InitUserCollection 初始化用户集合
func InitUserCollection(db *mongo.Database) error {
	// 获取JSON Schema
	validator := GetUserValidator()

	// 创建集合选项
	opts := options.CreateCollection().SetValidator(bson.M{
		"$jsonSchema": validator,
	})

	// 创建集合
	err := db.CreateCollection(context.Background(), "users", opts)
	if err != nil {
		// 如果集合已存在，更新验证规则
		if cmdErr, ok := err.(mongo.CommandError); ok && cmdErr.Code == 48 {
			cmd := bson.D{
				{"collMod", "users"},
				{"validator", bson.M{
					"$jsonSchema": validator,
				}},
				{"validationLevel", "strict"},
				{"validationAction", "error"},
			}
			err = db.RunCommand(context.Background(), cmd).Err()
		}
	}
	return err
}

// Initialize 初始化应用
func (app *App) Initialize() error {
	// 连接MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(app.config.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	// 验证连接
	err = client.Ping(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	app.db = client.Database(app.config.DatabaseName)

	// 初始化集合
	if err := app.InitializeCollections(); err != nil {
		return fmt.Errorf("failed to initialize collections: %v", err)
	}
	return nil
}

// authMiddleware JWT认证中间件
func (app *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从Header获取token
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			app.responseError(w, http.StatusUnauthorized, "无认证信息")
			return
		}

		// 解析token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(app.config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			app.responseError(w, http.StatusUnauthorized, "无效的认证信息")
			return
		}

		// 将认证信息存入context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// CORS中间件
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置允许的源，匹配请求的源或默认为 *
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		// 设置其他CORS相关头
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Length,Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,PATCH")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 处理预检请求
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// responseJSON 统一JSON响应
func (app *App) responseJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// responseError 错误响应
func (app *App) responseError(w http.ResponseWriter, code int, message string) {
	app.responseJSON(w, code, Response{
		Code:    code,
		Message: message,
	})
}

// responseSuccess 成功响应
func (app *App) responseSuccess(w http.ResponseWriter, data interface{}) {
	app.responseJSON(w, http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "success",
		Data:    data,
	})
}

// setupRoutes 设置路由
func (app *App) setupRoutes() {
	mux := http.NewServeMux()

	// API路由
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		app.responseSuccess(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/auth/login", app.login)
	mux.HandleFunc("POST /api/v1/auth/refresh", app.refreshToken)

	// 需要认证的API
	mux.HandleFunc("POST /api/v1/users", app.authMiddleware(app.createUser))
	mux.HandleFunc("GET /api/v1/users/{id}", app.authMiddleware(app.getUser))
	mux.HandleFunc("PUT /api/v1/users/{id}", app.authMiddleware(app.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", app.authMiddleware(app.deleteUser))

	// 应用CORS中间件
	app.httpServer = &http.Server{
		Handler:  corsMiddleware(mux),
		ErrorLog: nil,
	}
}

// InitDbAndColl 初始化数据库集合
func InitDbAndColl(client *mongo.Client, db, coll string, model map[string]interface{}) map[string]interface{} {
	// 检查集合是否存在
	tn, _ := client.Database(db).ListCollections(context.Background(), bson.M{"name": coll})
	if !tn.Next(context.Background()) {
		client.Database(db).RunCommand(context.Background(), bson.D{{"create", coll}})
	}

	// 设置验证规则
	result := client.Database(db).RunCommand(context.Background(), bson.D{
		{"collMod", coll},
		{"validator", model},
	})

	var res map[string]interface{}
	if err := result.Decode(&res); err != nil {
		log.Println(coll, err)
	}
	return res
}

// GenJsonSchema 生成JSON Schema
func GenJsonSchema(obj interface{}) map[string]interface{} {
	reflector := &mschema.Reflector{
		ExpandedStruct:             true,
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  true,
	}
	schema := reflector.Reflect(obj)

	// 转换为bson.M
	bts, _ := json.Marshal(schema)
	var schemaMap map[string]interface{}
	_ = json.Unmarshal(bts, &schemaMap)

	return bson.M{"$jsonSchema": schemaMap}
}

// InitializeCollections 初始化所有集合
func (app *App) InitializeCollections() error {
	// 初始化users集合
	res := InitDbAndColl(app.db.Client(), app.db.Name(), "users", GenJsonSchema(&User{}))
	// 创建索引
	indexView := app.db.Collection("users").Indexes()
	_, err := indexView.CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys:    bson.D{{"username", 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{"email", 1}},
			Options: options.Index().SetSparse(true),
		},
		{
			Keys:    bson.D{{"phone", 1}},
			Options: options.Index().SetSparse(true),
		},
	})
	if err != nil {
		log.Printf("Failed to create indexes for users collection: %v", err)
		return err
	}

	log.Printf("Users collection initialized: %v", res["ok"])
	return nil
}

// 修改User模型，添加jsonschema标签
type User struct {
	Username    string    `bson:"username" json:"username" jsonschema:"required,minLength=3,maxLength=32"`
	Password    string    `bson:"password" json:"-" jsonschema:"required,minLength=6,maxLength=64"`
	Email       string    `bson:"email" json:"email" jsonschema:"pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
	Phone       string    `bson:"phone" json:"phone" jsonschema:"pattern=^1[3-9]\\d{9}$"`
	Name        string    `bson:"name" json:"name" jsonschema:"required,minLength=2,maxLength=32"`
	Status      int       `bson:"status" json:"status" jsonschema:"enum=0|1"` // 0: 禁用, 1: 启用
	LastLoginAt time.Time `bson:"lastLoginAt" json:"lastLoginAt"`
	LastLoginIP string    `bson:"lastLoginIp" json:"lastLoginIp" jsonschema:"pattern=^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"`
	Roles       []string  `bson:"roles" json:"roles" jsonschema:"uniqueItems=true"`
}

func (app *App) createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		app.responseError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	// ... 处理创建用户逻辑 ...
}

func (app *App) getUser(w http.ResponseWriter, r *http.Request) {
	// 获取路径参数
	id := r.PathValue("id")
	if id == "" {
		app.responseError(w, http.StatusBadRequest, "Missing user ID")
		return
	}
	// ... 处理获取用户逻辑 ...
}

func (app *App) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.responseError(w, http.StatusBadRequest, "Missing user ID")
		return
	}
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		app.responseError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	// ... 处理更新用户逻辑 ...
}

func (app *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.responseError(w, http.StatusBadRequest, "Missing user ID")
		return
	}
	// ... 处理删除用户逻辑 ...
}

func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		app.responseError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	// ... 处理登录逻辑 ...
}

func (app *App) refreshToken(w http.ResponseWriter, r *http.Request) {
	// ... 处理token刷新逻辑 ...
}

// Run 运行应用
func (app *App) Run(addr string, certFile, keyFile string) error {
	app.setupRoutes()

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var socketErr error
			err := c.Control(func(fd uintptr) {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return socketErr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}

	// 信号处理
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	cleanup := make(chan bool)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动服务器
	if certFile != "" && keyFile != "" {
		go func() {
			if err := app.httpServer.ServeTLS(ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v\n", err)
			}
		}()
		log.Printf("Server starting on https://%s\n", addr)
	} else {
		go func() {
			if err := app.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v\n", err)
			}
		}()
		log.Printf("Server starting on http://%s\n", addr)
	}

	// 优雅退出处理
	go func() {
		for range signalChan {
			log.Println("Shutdown signal received")

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			go func() {
				if err := app.httpServer.Shutdown(ctx); err != nil {
					log.Printf("HTTP server shutdown error: %v\n", err)
				}
				if err := app.db.Client().Disconnect(ctx); err != nil {
					log.Printf("MongoDB disconnect error: %v\n", err)
				}
				cleanup <- true
			}()

			<-cleanup
			log.Println("Cleanup completed")
			cleanupDone <- true
		}
	}()

	<-cleanupDone
	return nil
}

func main() {
	config := &Config{
		MongoURI:     "mongodb://localhost:27017",
		DatabaseName: "tmind",
		JWTSecret:    "your-secret-key",
	}

	app := NewApp(config)
	if err := app.Initialize(); err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}

	// 支持 HTTP/HTTPS
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	addr := ":8080" // 可以通过环境变量或命令行参数配置

	if err := app.Run(addr, certFile, keyFile); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
