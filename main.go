package main

import (
	"T-Mind_/mschema"
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

func (app *App) enterpriseMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("claims").(*Claims)
		if !ok {
			app.responseError(w, http.StatusUnauthorized, "无效的认证信息")
			return
		}

		// 转换用户ID
		uid, err := primitive.ObjectIDFromHex(claims.UserID)
		if err != nil {
			app.responseError(w, http.StatusBadRequest, "无效的用户ID")
			return
		}

		// 转换企业ID
		eid, err := primitive.ObjectIDFromHex(claims.CurrentEnt)
		if err != nil {
			app.responseError(w, http.StatusBadRequest, "无效的企业ID")
			return
		}

		// 验证企业访问权限
		userEnt := UserEnterprise{}
		err = app.db.Collection("user_enterprises").FindOne(
			r.Context(),
			bson.M{
				"userId":       uid,
				"enterpriseId": eid,
				"status":       1,
			},
		).Decode(&userEnt)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				app.responseError(w, http.StatusForbidden, "无企业访问权限")
				return
			}
			app.responseError(w, http.StatusInternalServerError, "验证企业权限失败")
			return
		}

		// 将企业信息注入上下文
		ctx := context.WithValue(r.Context(), "enterprise", userEnt)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
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

	// 企业相关路由
	mux.HandleFunc("POST /api/v1/enterprises", app.authMiddleware(app.createEnterprise))
	mux.HandleFunc("GET /api/v1/enterprises", app.authMiddleware(app.listEnterprises))
	mux.HandleFunc("GET /api/v1/enterprises/current", app.authMiddleware(app.getCurrentEnterprise))
	mux.HandleFunc("PUT /api/v1/enterprises/{id}", app.authMiddleware(app.updateEnterprise))
	mux.HandleFunc("POST /api/v1/enterprises/switch", app.authMiddleware(app.switchEnterprise))

	// 用户-企业关联
	mux.HandleFunc("POST /api/v1/enterprises/{id}/users", app.authMiddleware(app.addEnterpriseUser))
	mux.HandleFunc("DELETE /api/v1/enterprises/{id}/users/{userId}", app.authMiddleware(app.removeEnterpriseUser))
	mux.HandleFunc("PUT /api/v1/enterprises/{id}/users/{userId}/role", app.authMiddleware(app.updateUserRole))

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
	// 初始化企业集合
	res = InitDbAndColl(app.db.Client(), app.db.Name(), "enterprises", GenJsonSchema(&Enterprise{}))

	// 创建企业集合索引
	_, err = app.db.Collection("enterprises").Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys:    bson.D{{"creditCode", 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{"name", 1}},
			Options: options.Index().SetUnique(true),
		},
	})

	if err != nil {
		log.Printf("Failed to create indexes for enterprises collection: %v", err)
		return err
	}
	log.Printf("enterprises collection initialized: %v", res["ok"])
	// 初始化用户-企业关联集合
	res = InitDbAndColl(app.db.Client(), app.db.Name(), "user_enterprises", GenJsonSchema(&UserEnterprise{}))

	// 创建关联集合索引
	_, err = app.db.Collection("user_enterprises").Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys:    bson.D{{"userId", 1}, {"enterpriseId", 1}},
			Options: options.Index().SetUnique(true),
		},
	})

	if err != nil {
		log.Printf("Failed to create indexes for user_enterprises collection: %v", err)
		return err
	}
	log.Printf("user_enterprises collection initialized: %v", res["ok"])
	return nil
}

type Enterprise struct {
	Id          primitive.ObjectID `bson:"_id,omitempty" json:"id" jsonschema:"required"`
	CreditCode  string             `bson:"creditCode" json:"creditCode" jsonschema:"required,pattern=^[0-9A-Z]{18}$"`
	Name        string             `bson:"name" json:"name" jsonschema:"required,minLength=2,maxLength=100"`
	AdminUserID primitive.ObjectID `bson:"adminUserId" json:"adminUserId" jsonschema:"required"`
	Status      int                `bson:"status" json:"status" jsonschema:"enum=0|1"`
	CreatedAt   time.Time          `bson:"createdAt" json:"createdAt"`
	ExpireAt    time.Time          `bson:"expireAt" json:"expireAt"`
	ContactInfo struct {
		Name  string `bson:"name" json:"name" jsonschema:"required"`
		Phone string `bson:"phone" json:"phone" jsonschema:"pattern=^1[3-9]\\d{9}$"`
		Email string `bson:"email" json:"email" jsonschema:"pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
	} `bson:"contactInfo" json:"contactInfo" jsonschema:"type=object"`
	Config map[string]interface{} `bson:"config" json:"config" jsonschema:"type=object"`
}

type UserEnterprise struct {
	Id           primitive.ObjectID `json:"id" bson:"_id"`
	UserID       primitive.ObjectID `bson:"userId" json:"userId" jsonschema:"required"`
	EnterpriseID primitive.ObjectID `bson:"enterpriseId" json:"enterpriseId" jsonschema:"required"`
	Role         string             `bson:"role" json:"role" jsonschema:"required,enum=admin|user|guest"`
	Status       int                `bson:"status" json:"status" jsonschema:"enum=0|1"`
	JoinTime     time.Time          `bson:"joinTime" json:"joinTime"`
	LastAccess   time.Time          `bson:"lastAccess" json:"lastAccess"`
}

func (app *App) switchEnterprise(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnterpriseID string `json:"enterpriseId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	eid, err := primitive.ObjectIDFromHex(req.EnterpriseID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	userEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       uid,
			"enterpriseId": eid,
			"status":       1,
		},
	).Decode(&userEnt)

	if err != nil {
		app.responseError(w, http.StatusForbidden, "无权访问该企业")
		return
	}

	// 生成新token
	user := &User{Id: uid}
	token, err := app.generateToken(user, req.EnterpriseID, []string{userEnt.Role})
	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "Token生成失败")
		return
	}

	app.responseSuccess(w, map[string]string{"token": token})
}

// 创建企业
func (app *App) createEnterprise(w http.ResponseWriter, r *http.Request) {
	var enterprise Enterprise
	if err := json.NewDecoder(r.Body).Decode(&enterprise); err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	// 获取当前用户信息
	claims := r.Context().Value("claims").(*Claims)

	// 设置基础字段
	enterprise.Id = primitive.NewObjectID()
	enterprise.CreatedAt = time.Now()
	uid, _ := primitive.ObjectIDFromHex(claims.UserID)
	enterprise.AdminUserID = uid
	enterprise.Status = 1

	// 检查信用代码是否已存在
	exists, err := app.db.Collection("enterprises").CountDocuments(
		r.Context(),
		bson.M{"creditCode": enterprise.CreditCode},
	)
	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "数据库查询错误")
		return
	}
	if exists > 0 {
		app.responseError(w, http.StatusBadRequest, "企业信用代码已存在")
		return
	}

	// 创建企业
	_, err = app.db.Collection("enterprises").InsertOne(r.Context(), enterprise)
	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "创建企业失败")
		return
	}

	uid, _ = primitive.ObjectIDFromHex(claims.UserID)
	// 创建用户-企业关联（将创建者设为管理员）
	userEnterprise := UserEnterprise{
		Id:           primitive.NewObjectID(),
		UserID:       uid,
		EnterpriseID: enterprise.Id,
		Role:         "admin",
		Status:       1,
		JoinTime:     time.Now(),
		LastAccess:   time.Now(),
	}

	_, err = app.db.Collection("user_enterprises").InsertOne(r.Context(), userEnterprise)
	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "创建用户企业关联失败")
		return
	}

	app.responseSuccess(w, enterprise)
}

// 获取企业列表
func (app *App) listEnterprises(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	// 查询用户关联的所有企业
	cursor, err := app.db.Collection("user_enterprises").Aggregate(r.Context(), []bson.M{
		{
			"$match": bson.M{
				"userId": uid,
				"status": 1,
			},
		},
		{
			"$lookup": bson.M{
				"from":         "enterprises",
				"localField":   "enterpriseId",
				"foreignField": "_id",
				"as":           "enterprise",
			},
		},
		{
			"$unwind": "$enterprise",
		},
		{
			"$project": bson.M{
				"enterprise": 1,
				"role":       1,
				"joinTime":   1,
			},
		},
	})

	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	defer cursor.Close(r.Context())

	var results []map[string]interface{}
	if err = cursor.All(r.Context(), &results); err != nil {
		app.responseError(w, http.StatusInternalServerError, "解析数据失败")
		return
	}

	app.responseSuccess(w, results)
}

// 获取当前企业信息
func (app *App) getCurrentEnterprise(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	eid, err := primitive.ObjectIDFromHex(claims.CurrentEnt)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	var enterprise Enterprise
	err = app.db.Collection("enterprises").FindOne(
		r.Context(),
		bson.M{"_id": eid},
	).Decode(&enterprise)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.responseError(w, http.StatusNotFound, "企业不存在")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "查询失败")
		return
	}

	app.responseSuccess(w, enterprise)
}

// 更新企业信息
func (app *App) updateEnterprise(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.responseError(w, http.StatusBadRequest, "缺少企业ID")
		return
	}

	eid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	// 验证权限
	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	userEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       uid,
			"enterpriseId": eid,
			"role":         "admin",
			"status":       1,
		},
	).Decode(&userEnt)

	if err != nil {
		app.responseError(w, http.StatusForbidden, "无权限更新企业信息")
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	// 删除不允许更新的字段
	delete(updateData, "_id")
	delete(updateData, "creditCode")
	delete(updateData, "adminUserId")
	delete(updateData, "createdAt")

	update := bson.M{"$set": updateData}
	result, err := app.db.Collection("enterprises").UpdateOne(
		r.Context(),
		bson.M{"_id": eid}, // 使用已转换的eid
		update,
	)

	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "更新失败")
		return
	}

	if result.ModifiedCount == 0 {
		app.responseError(w, http.StatusNotFound, "企业不存在")
		return
	}

	app.responseSuccess(w, map[string]interface{}{"modified": result.ModifiedCount})
}

// 添加企业用户
func (app *App) addEnterpriseUser(w http.ResponseWriter, r *http.Request) {
	enterpriseId := r.PathValue("id")
	if enterpriseId == "" {
		app.responseError(w, http.StatusBadRequest, "缺少企业ID")
		return
	}

	// 转换企业ID
	eid, err := primitive.ObjectIDFromHex(enterpriseId)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	var req struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	// 验证用户ID格式
	newUserId, err := primitive.ObjectIDFromHex(req.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	// 验证角色值
	if req.Role != "admin" && req.Role != "user" && req.Role != "guest" {
		app.responseError(w, http.StatusBadRequest, "无效的角色值")
		return
	}

	// 验证当前用户权限
	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的认证信息")
		return
	}

	// 检查当前用户是否是企业管理员
	adminEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       uid,
			"enterpriseId": eid,
			"role":         "admin",
			"status":       1,
		},
	).Decode(&adminEnt)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.responseError(w, http.StatusForbidden, "无权限添加用户")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "验证权限失败")
		return
	}

	// 检查目标用户是否存在
	var targetUser User
	err = app.db.Collection("users").FindOne(
		r.Context(),
		bson.M{"_id": newUserId},
	).Decode(&targetUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.responseError(w, http.StatusNotFound, "目标用户不存在")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "查询用户失败")
		return
	}

	// 检查用户是否已经在企业中
	existingEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       newUserId,
			"enterpriseId": eid,
			"status":       1,
		},
	).Decode(&existingEnt)

	if err == nil {
		app.responseError(w, http.StatusBadRequest, "用户已在企业中")
		return
	} else if err != mongo.ErrNoDocuments {
		app.responseError(w, http.StatusInternalServerError, "查询用户企业关联失败")
		return
	}

	// 创建用户-企业关联
	userEnterprise := UserEnterprise{
		Id:           primitive.NewObjectID(),
		UserID:       newUserId,
		EnterpriseID: eid,
		Role:         req.Role,
		Status:       1,
		JoinTime:     time.Now(),
		LastAccess:   time.Now(),
	}

	_, err = app.db.Collection("user_enterprises").InsertOne(r.Context(), userEnterprise)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			app.responseError(w, http.StatusBadRequest, "用户已在企业中")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "添加用户失败")
		return
	}

	// 构建响应数据
	responseData := map[string]interface{}{
		"userEnterprise": userEnterprise,
		"user": map[string]interface{}{
			"id":       targetUser.Id,
			"username": targetUser.Username,
			"name":     targetUser.Name,
			"email":    targetUser.Email,
			"phone":    targetUser.Phone,
		},
	}

	app.responseSuccess(w, responseData)
}

// 移除企业用户
func (app *App) removeEnterpriseUser(w http.ResponseWriter, r *http.Request) {
	enterpriseId := r.PathValue("id")
	userId := r.PathValue("userId")
	if enterpriseId == "" || userId == "" {
		app.responseError(w, http.StatusBadRequest, "缺少必要参数")
		return
	}

	// 转换企业ID
	eid, err := primitive.ObjectIDFromHex(enterpriseId)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	// 转换要移除的用户ID
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	// 获取当前操作用户的ID
	claims := r.Context().Value("claims").(*Claims)
	adminUid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的认证信息")
		return
	}

	// 不能移除自己
	if adminUid == uid {
		app.responseError(w, http.StatusBadRequest, "不能移除自己")
		return
	}

	// 验证当前用户是否是企业管理员
	adminEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       adminUid,
			"enterpriseId": eid,
			"role":         "admin",
			"status":       1,
		},
	).Decode(&adminEnt)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.responseError(w, http.StatusForbidden, "无权限移除用户")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "验证权限失败")
		return
	}

	// 检查要移除的用户是否存在于企业中
	userEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       uid,
			"enterpriseId": eid,
			"status":       1,
		},
	).Decode(&userEnt)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.responseError(w, http.StatusNotFound, "用户不在企业中或已被移除")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "查询用户企业关联失败")
		return
	}

	// 如果要移除的用户也是管理员，确保还有其他管理员
	if userEnt.Role == "admin" {
		adminCount, err := app.db.Collection("user_enterprises").CountDocuments(
			r.Context(),
			bson.M{
				"enterpriseId": eid,
				"role":         "admin",
				"status":       1,
			},
		)
		if err != nil {
			app.responseError(w, http.StatusInternalServerError, "查询管理员数量失败")
			return
		}
		if adminCount <= 1 {
			app.responseError(w, http.StatusBadRequest, "不能移除最后一个管理员")
			return
		}
	}

	// 软删除用户-企业关联
	result, err := app.db.Collection("user_enterprises").UpdateOne(
		r.Context(),
		bson.M{
			"userId":       uid,
			"enterpriseId": eid,
			"status":       1,
		},
		bson.M{
			"$set": bson.M{
				"status":     0,
				"updateTime": time.Now(),
			},
		},
	)

	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "移除用户失败")
		return
	}

	if result.ModifiedCount == 0 {
		app.responseError(w, http.StatusNotFound, "用户不在企业中或已被移除")
		return
	}

	app.responseSuccess(w, map[string]interface{}{
		"modified": result.ModifiedCount,
		"message":  "用户已成功从企业中移除",
	})
}

// 更新用户角色
func (app *App) updateUserRole(w http.ResponseWriter, r *http.Request) {
	enterpriseId := r.PathValue("id")
	userId := r.PathValue("userId")
	if enterpriseId == "" || userId == "" {
		app.responseError(w, http.StatusBadRequest, "缺少必要参数")
		return
	}

	// 转换用户ID和企业ID
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	eid, err := primitive.ObjectIDFromHex(enterpriseId)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	// 验证当前用户权限
	claims := r.Context().Value("claims").(*Claims)
	adminUid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.responseError(w, http.StatusBadRequest, "无效的认证信息")
		return
	}

	// 不能更新自己的角色
	if claims.UserID == userId {
		app.responseError(w, http.StatusBadRequest, "不能更新自己的角色")
		return
	}

	adminEnt := UserEnterprise{}
	err = app.db.Collection("user_enterprises").FindOne(
		r.Context(),
		bson.M{
			"userId":       adminUid,
			"enterpriseId": eid,
			"role":         "admin",
			"status":       1,
		},
	).Decode(&adminEnt)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.responseError(w, http.StatusForbidden, "无权限更新角色")
			return
		}
		app.responseError(w, http.StatusInternalServerError, "验证权限失败")
		return
	}

	// 如果要更改的是管理员角色，确保还有其他管理员
	if req.Role != "admin" {
		count, err := app.db.Collection("user_enterprises").CountDocuments(
			r.Context(),
			bson.M{
				"enterpriseId": eid,
				"role":         "admin",
				"status":       1,
			},
		)
		if err != nil {
			app.responseError(w, http.StatusInternalServerError, "查询管理员数量失败")
			return
		}
		if count <= 1 {
			app.responseError(w, http.StatusBadRequest, "必须保留至少一个管理员")
			return
		}
	}

	result, err := app.db.Collection("user_enterprises").UpdateOne(
		r.Context(),
		bson.M{
			"userId":       uid,
			"enterpriseId": eid,
			"status":       1,
		},
		bson.M{
			"$set": bson.M{
				"role":       req.Role,
				"updateTime": time.Now(),
			},
		},
	)

	if err != nil {
		app.responseError(w, http.StatusInternalServerError, "更新角色失败")
		return
	}

	if result.ModifiedCount == 0 {
		app.responseError(w, http.StatusNotFound, "用户不存在或已被移除")
		return
	}

	app.responseSuccess(w, map[string]interface{}{
		"modified": result.ModifiedCount,
		"message":  "用户角色已更新",
	})
}

// 修改User模型，添加jsonschema标签
type User struct {
	Id          primitive.ObjectID `json:"id" bson:"_id"`
	Username    string             `bson:"username" json:"username" jsonschema:"required,minLength=3,maxLength=32"`
	Password    string             `bson:"password" json:"-" jsonschema:"required,minLength=6,maxLength=64"`
	Email       string             `bson:"email" json:"email" jsonschema:"pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
	Phone       string             `bson:"phone" json:"phone" jsonschema:"pattern=^1[3-9]\\d{9}$"`
	Name        string             `bson:"name" json:"name" jsonschema:"required,minLength=2,maxLength=32"`
	Status      int                `bson:"status" json:"status" jsonschema:"enum=0|1"` // 0: 禁用, 1: 启用
	LastLoginAt time.Time          `bson:"lastLoginAt" json:"lastLoginAt"`
	LastLoginIP string             `bson:"lastLoginIp" json:"lastLoginIp" jsonschema:"pattern=^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"`
	Roles       []string           `bson:"roles" json:"roles" jsonschema:"uniqueItems=true"`
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
