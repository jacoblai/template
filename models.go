package main

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// Collection names
const (
	TUsers           = "users"
	TEnterprises     = "enterprises"
	TUserEnterprises = "user_enterprises"
)

// Enterprise 企业模型
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

// UserEnterprise 用户-企业关联模型
type UserEnterprise struct {
	Id           primitive.ObjectID `json:"id" bson:"_id"`
	UserID       primitive.ObjectID `bson:"userId" json:"userId" jsonschema:"required"`
	EnterpriseID primitive.ObjectID `bson:"enterpriseId" json:"enterpriseId" jsonschema:"required"`
	Role         string             `bson:"role" json:"role" jsonschema:"required,enum=admin|user|guest"`
	Status       int                `bson:"status" json:"status" jsonschema:"enum=0|1"`
	JoinTime     time.Time          `bson:"joinTime" json:"joinTime"`
	LastAccess   time.Time          `bson:"lastAccess" json:"lastAccess"`
}

// User 用户模型
type User struct {
	Id          primitive.ObjectID `json:"id" bson:"_id"`
	Username    string             `bson:"username" json:"username" jsonschema:"required,minLength=3,maxLength=32"`
	Password    string             `bson:"password" json:"-" jsonschema:"required,minLength=6,maxLength=64"`
	Email       string             `bson:"email" json:"email" jsonschema:"pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
	Phone       string             `bson:"phone" json:"phone" jsonschema:"pattern=^1[3-9]\\d{9}$"`
	Name        string             `bson:"name" json:"name" jsonschema:"required,minLength=2,maxLength=32"`
	Status      int                `bson:"status" json:"status" jsonschema:"enum=0|1"`
	LastLoginAt time.Time          `bson:"lastLoginAt" json:"lastLoginAt"`
	LastLoginIP string             `bson:"lastLoginIp" json:"lastLoginIp" jsonschema:"pattern=^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"`
	Roles       []string           `bson:"roles" json:"roles" jsonschema:"uniqueItems=true"`
}
