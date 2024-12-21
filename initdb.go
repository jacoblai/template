package main

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
)

// InitializeCollections 初始化所有集合
func (app *App) InitializeCollections() error {
	// 初始化users集合
	res := InitDbAndColl(app.db.Client(), app.db.Name(), TUsers, GenJsonSchema(&User{}))
	// 创建users索引
	_, err := app.GetColl(TUsers).Indexes().CreateMany(context.Background(), []mongo.IndexModel{
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
		log.Printf("Failed to create indexes for %s collection: %v", TUsers, err)
		return err
	}
	log.Printf("%s collection initialized: %v", TUsers, res["ok"])
	// 初始化enterprises集合
	res = InitDbAndColl(app.db.Client(), app.db.Name(), TEnterprises, GenJsonSchema(&Enterprise{}))
	// 创建enterprises索引
	_, err = app.GetColl(TEnterprises).Indexes().CreateMany(context.Background(), []mongo.IndexModel{
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
		log.Printf("Failed to create indexes for %s collection: %v", TEnterprises, err)
		return err
	}
	log.Printf("%s collection initialized: %v", TEnterprises, res["ok"])
	// 初始化user_enterprises集合
	res = InitDbAndColl(app.db.Client(), app.db.Name(), TUserEnterprises, GenJsonSchema(&UserEnterprise{}))
	// 创建user_enterprises索引
	_, err = app.GetColl(TUserEnterprises).Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		{
			Keys:    bson.D{{"userId", 1}, {"enterpriseId", 1}},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		log.Printf("Failed to create indexes for %s collection: %v", TUserEnterprises, err)
		return err
	}
	log.Printf("%s collection initialized: %v", TUserEnterprises, res["ok"])

	return nil
}
