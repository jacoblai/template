package main

import (
	"T-Mind/mschema"
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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
	UserID       string   `json:"userId"`
	EnterpriseID string   `json:"enterpriseId"`
	Roles        []string `json:"roles"`
	CurrentEnt   string   `json:"currentEnt"` // 当前选择的企业
	jwt.RegisteredClaims
}

// Token生成函数
func (app *App) generateToken(user *User, enterpriseId string, roles []string) (string, error) {
	claims := &Claims{
		UserID:       user.Id.Hex(),
		EnterpriseID: enterpriseId,
		Roles:        roles,
		CurrentEnt:   enterpriseId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(app.config.JWTSecret))
}

// NewApp 创建应用实例
func NewApp(config *Config) *App {
	return &App{
		config: config,
	}
}

// Initialize 初始化应用
func (app *App) Initialize() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(app.config.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	app.db = client.Database(app.config.DatabaseName)

	if err := app.InitializeCollections(); err != nil {
		return fmt.Errorf("failed to initialize collections: %v", err)
	}
	return nil
}

// authMiddleware JWT认证中间件
func (app *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			app.resError(w, http.StatusUnauthorized, "无认证信息")
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(app.config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			app.resError(w, http.StatusUnauthorized, "无效的认证信息")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// CORS中间件
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Length,Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,PATCH")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// enterpriseMiddleware 企业权限中间件
func (app *App) enterpriseMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("claims").(*Claims)
		if !ok {
			app.resError(w, http.StatusUnauthorized, "无效的认证信息")
			return
		}

		uid, err := primitive.ObjectIDFromHex(claims.UserID)
		if err != nil {
			app.resError(w, http.StatusBadRequest, "无效的用户ID")
			return
		}

		eid, err := primitive.ObjectIDFromHex(claims.CurrentEnt)
		if err != nil {
			app.resError(w, http.StatusBadRequest, "无效的企业ID")
			return
		}

		userEnt := UserEnterprise{}
		err = app.GetColl(TUserEnterprises).FindOne(
			r.Context(),
			bson.M{
				"userId":       uid,
				"enterpriseId": eid,
				"status":       1,
			},
		).Decode(&userEnt)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				app.resError(w, http.StatusForbidden, "无企业访问权限")
				return
			}
			app.resError(w, http.StatusInternalServerError, "验证企业权限失败")
			return
		}

		ctx := context.WithValue(r.Context(), "enterprise", userEnt)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// resJSON 统一JSON响应
func (app *App) resJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// resError 错误响应
func (app *App) resError(w http.ResponseWriter, code int, message string) {
	app.resJSON(w, code, Response{
		Code:    code,
		Message: message,
	})
}

// resSuccess 成功响应
func (app *App) resSuccess(w http.ResponseWriter, data interface{}) {
	app.resJSON(w, http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "success",
		Data:    data,
	})
}

// setupRoutes 设置路由
func (app *App) setupRoutes() {
	mux := http.NewServeMux()

	// 健康检查
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		app.resSuccess(w, map[string]string{"status": "ok"})
	})

	// 认证相关
	mux.HandleFunc("POST /api/v1/auth/login", app.login)
	mux.HandleFunc("POST /api/v1/auth/refresh", app.refreshToken)

	// 用户管理
	mux.HandleFunc("POST /api/v1/users", app.authMiddleware(app.createUser))
	mux.HandleFunc("GET /api/v1/users/{id}", app.authMiddleware(app.getUser))
	mux.HandleFunc("PUT /api/v1/users/{id}", app.authMiddleware(app.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{id}", app.authMiddleware(app.deleteUser))

	// 企业管理
	mux.HandleFunc("POST /api/v1/enterprises", app.authMiddleware(app.createEnterprise))
	mux.HandleFunc("GET /api/v1/enterprises", app.authMiddleware(app.listEnterprises))
	mux.HandleFunc("GET /api/v1/enterprises/current", app.authMiddleware(app.getCurrentEnterprise))
	mux.HandleFunc("PUT /api/v1/enterprises/{id}", app.authMiddleware(app.updateEnterprise))
	mux.HandleFunc("POST /api/v1/enterprises/switch", app.authMiddleware(app.switchEnterprise))

	// 用户-企业关联管理
	mux.HandleFunc("POST /api/v1/enterprises/{id}/users", app.authMiddleware(app.addEnterpriseUser))
	mux.HandleFunc("DELETE /api/v1/enterprises/{id}/users/{userId}", app.authMiddleware(app.removeEnterpriseUser))
	mux.HandleFunc("PUT /api/v1/enterprises/{id}/users/{userId}/role", app.authMiddleware(app.updateUserRole))

	app.httpServer = &http.Server{
		Handler:  corsMiddleware(mux),
		ErrorLog: nil,
	}
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

	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	cleanup := make(chan bool)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

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

	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	addr := ":8080"

	if err := app.Run(addr, certFile, keyFile); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// GetColl 获取集合实例
func (app *App) GetColl(coll string) *mongo.Collection {
	col, _ := app.db.Collection(coll).Clone()
	return col
}

// InitDbAndColl 初始化数据库集合
func InitDbAndColl(client *mongo.Client, db, coll string, model map[string]interface{}) map[string]interface{} {
	tn, _ := client.Database(db).ListCollections(context.Background(), bson.M{"name": coll})
	if !tn.Next(context.Background()) {
		client.Database(db).RunCommand(context.Background(), bson.D{{"create", coll}})
	}

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

	bts, _ := json.Marshal(schema)
	var schemaMap map[string]interface{}
	_ = json.Unmarshal(bts, &schemaMap)

	return bson.M{"$jsonSchema": schemaMap}
}
