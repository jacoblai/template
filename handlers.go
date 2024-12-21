package main

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"time"
)

// 以下是API处理函数的基本实现

func (app *App) createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		app.resError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	// TODO: 实现创建用户逻辑
}

func (app *App) getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.resError(w, http.StatusBadRequest, "Missing user ID")
		return
	}
	// TODO: 实现获取用户逻辑
}

func (app *App) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.resError(w, http.StatusBadRequest, "Missing user ID")
		return
	}
	// TODO: 实现更新用户逻辑
}

func (app *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.resError(w, http.StatusBadRequest, "Missing user ID")
		return
	}
	// TODO: 实现删除用户逻辑
}

func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		app.resError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	// TODO: 实现登录逻辑
}

func (app *App) refreshToken(w http.ResponseWriter, r *http.Request) {
	// TODO: 实现token刷新逻辑
}

func (app *App) switchEnterprise(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnterpriseID string `json:"enterpriseId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.resError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	eid, err := primitive.ObjectIDFromHex(req.EnterpriseID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的企业ID")
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
		app.resError(w, http.StatusForbidden, "无权访问该企业")
		return
	}

	// 生成新token
	user := &User{Id: uid}
	token, err := app.generateToken(user, req.EnterpriseID, []string{userEnt.Role})
	if err != nil {
		app.resError(w, http.StatusInternalServerError, "Token生成失败")
		return
	}

	app.resSuccess(w, map[string]string{"token": token})
}

// 创建企业
func (app *App) createEnterprise(w http.ResponseWriter, r *http.Request) {
	var enterprise Enterprise
	if err := json.NewDecoder(r.Body).Decode(&enterprise); err != nil {
		app.resError(w, http.StatusBadRequest, "无效的请求数据")
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
		app.resError(w, http.StatusInternalServerError, "数据库查询错误")
		return
	}
	if exists > 0 {
		app.resError(w, http.StatusBadRequest, "企业信用代码已存在")
		return
	}

	// 创建企业
	_, err = app.db.Collection("enterprises").InsertOne(r.Context(), enterprise)
	if err != nil {
		app.resError(w, http.StatusInternalServerError, "创建企业失败")
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
		app.resError(w, http.StatusInternalServerError, "创建用户企业关联失败")
		return
	}

	app.resSuccess(w, enterprise)
}

// 获取企业列表
func (app *App) listEnterprises(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的用户ID")
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
		app.resError(w, http.StatusInternalServerError, "查询失败")
		return
	}
	defer cursor.Close(r.Context())

	var results []map[string]interface{}
	if err = cursor.All(r.Context(), &results); err != nil {
		app.resError(w, http.StatusInternalServerError, "解析数据失败")
		return
	}

	app.resSuccess(w, results)
}

// 获取当前企业信息
func (app *App) getCurrentEnterprise(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	eid, err := primitive.ObjectIDFromHex(claims.CurrentEnt)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	var enterprise Enterprise
	err = app.db.Collection("enterprises").FindOne(
		r.Context(),
		bson.M{"_id": eid},
	).Decode(&enterprise)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			app.resError(w, http.StatusNotFound, "企业不存在")
			return
		}
		app.resError(w, http.StatusInternalServerError, "查询失败")
		return
	}

	app.resSuccess(w, enterprise)
}

// 更新企业信息
func (app *App) updateEnterprise(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		app.resError(w, http.StatusBadRequest, "缺少企业ID")
		return
	}

	eid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	// 验证权限
	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的用户ID")
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
		app.resError(w, http.StatusForbidden, "无权限更新企业信息")
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		app.resError(w, http.StatusBadRequest, "无效的请求数据")
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
		app.resError(w, http.StatusInternalServerError, "更新失败")
		return
	}

	if result.ModifiedCount == 0 {
		app.resError(w, http.StatusNotFound, "企业不存在")
		return
	}

	app.resSuccess(w, map[string]interface{}{"modified": result.ModifiedCount})
}

// 添加企业用户
func (app *App) addEnterpriseUser(w http.ResponseWriter, r *http.Request) {
	enterpriseId := r.PathValue("id")
	if enterpriseId == "" {
		app.resError(w, http.StatusBadRequest, "缺少企业ID")
		return
	}

	// 转换企业ID
	eid, err := primitive.ObjectIDFromHex(enterpriseId)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	var req struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.resError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	// 验证用户ID格式
	newUserId, err := primitive.ObjectIDFromHex(req.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	// 验证角色值
	if req.Role != "admin" && req.Role != "user" && req.Role != "guest" {
		app.resError(w, http.StatusBadRequest, "无效的角色值")
		return
	}

	// 验证当前用户权限
	claims := r.Context().Value("claims").(*Claims)
	uid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的认证信息")
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
			app.resError(w, http.StatusForbidden, "无权限添加用户")
			return
		}
		app.resError(w, http.StatusInternalServerError, "验证权限失败")
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
			app.resError(w, http.StatusNotFound, "目标用户不存在")
			return
		}
		app.resError(w, http.StatusInternalServerError, "查询用户失败")
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
		app.resError(w, http.StatusBadRequest, "用户已在企业中")
		return
	} else if err != mongo.ErrNoDocuments {
		app.resError(w, http.StatusInternalServerError, "查询用户企业关联失败")
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
			app.resError(w, http.StatusBadRequest, "用户已在企业中")
			return
		}
		app.resError(w, http.StatusInternalServerError, "添加用户失败")
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

	app.resSuccess(w, responseData)
}

// 移除企业用户
func (app *App) removeEnterpriseUser(w http.ResponseWriter, r *http.Request) {
	enterpriseId := r.PathValue("id")
	userId := r.PathValue("userId")
	if enterpriseId == "" || userId == "" {
		app.resError(w, http.StatusBadRequest, "缺少必要参数")
		return
	}

	// 转换企业ID
	eid, err := primitive.ObjectIDFromHex(enterpriseId)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	// 转换要移除的用户ID
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	// 获取当前操作用户的ID
	claims := r.Context().Value("claims").(*Claims)
	adminUid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的认证信息")
		return
	}

	// 不能移除自己
	if adminUid == uid {
		app.resError(w, http.StatusBadRequest, "不能移除自己")
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
			app.resError(w, http.StatusForbidden, "无权限移除用户")
			return
		}
		app.resError(w, http.StatusInternalServerError, "验证权限失败")
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
			app.resError(w, http.StatusNotFound, "用户不在企业中或已被移除")
			return
		}
		app.resError(w, http.StatusInternalServerError, "查询用户企业关联失败")
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
			app.resError(w, http.StatusInternalServerError, "查询管理员数量失败")
			return
		}
		if adminCount <= 1 {
			app.resError(w, http.StatusBadRequest, "不能移除最后一个管理员")
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
		app.resError(w, http.StatusInternalServerError, "移除用户失败")
		return
	}

	if result.ModifiedCount == 0 {
		app.resError(w, http.StatusNotFound, "用户不在企业中或已被移除")
		return
	}

	app.resSuccess(w, map[string]interface{}{
		"modified": result.ModifiedCount,
		"message":  "用户已成功从企业中移除",
	})
}

// 更新用户角色
func (app *App) updateUserRole(w http.ResponseWriter, r *http.Request) {
	enterpriseId := r.PathValue("id")
	userId := r.PathValue("userId")
	if enterpriseId == "" || userId == "" {
		app.resError(w, http.StatusBadRequest, "缺少必要参数")
		return
	}

	// 转换用户ID和企业ID
	uid, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的用户ID")
		return
	}

	eid, err := primitive.ObjectIDFromHex(enterpriseId)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的企业ID")
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		app.resError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	// 验证当前用户权限
	claims := r.Context().Value("claims").(*Claims)
	adminUid, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		app.resError(w, http.StatusBadRequest, "无效的认证信息")
		return
	}

	// 不能更新自己的角色
	if claims.UserID == userId {
		app.resError(w, http.StatusBadRequest, "不能更新自己的角色")
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
			app.resError(w, http.StatusForbidden, "无权限更新角色")
			return
		}
		app.resError(w, http.StatusInternalServerError, "验证权限失败")
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
			app.resError(w, http.StatusInternalServerError, "查询管理员数量失败")
			return
		}
		if count <= 1 {
			app.resError(w, http.StatusBadRequest, "必须保留至少一个管理员")
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
		app.resError(w, http.StatusInternalServerError, "更新角色失败")
		return
	}

	if result.ModifiedCount == 0 {
		app.resError(w, http.StatusNotFound, "用户不存在或已被移除")
		return
	}

	app.resSuccess(w, map[string]interface{}{
		"modified": result.ModifiedCount,
		"message":  "用户角色已更新",
	})
}
