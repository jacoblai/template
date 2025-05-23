package mschema

import (
	"encoding/json"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Version is the JSON Schema version.
// If extending JSON Schema with custom values use a custom URI.
// RFC draft-wright-json-schema-00, section 6
var Version = "http://json-schema.org/draft-04/schema#"

// Schema is the root schema.
// RFC draft-wright-json-schema-00, section 4.5
type Schema struct {
	*Type
}

// Type represents a JSON Schema object type.
type Type struct {
	// RFC draft-wright-json-schema-00
	//Version string `json:"$schema,omitempty"` // section 6.1
	Ref string `json:"$ref,omitempty"` // section 7
	// RFC draft-wright-json-schema-validation-00, section 5
	MultipleOf           int              `json:"multipleOf,omitempty"`           // section 5.1
	Maximum              *int             `json:"maximum,omitempty"`              // section 5.2
	ExclusiveMaximum     bool             `json:"exclusiveMaximum,omitempty"`     // section 5.3
	Minimum              *int             `json:"minimum,omitempty"`              // section 5.4
	ExclusiveMinimum     bool             `json:"exclusiveMinimum,omitempty"`     // section 5.5
	MaxLength            int              `json:"maxLength,omitempty"`            // section 5.6
	MinLength            int              `json:"minLength,omitempty"`            // section 5.7
	Pattern              string           `json:"pattern,omitempty"`              // section 5.8
	AdditionalItems      *Type            `json:"additionalItems,omitempty"`      // section 5.9
	Items                *Type            `json:"items,omitempty"`                // section 5.9
	MaxItems             int              `json:"maxItems,omitempty"`             // section 5.10
	MinItems             int              `json:"minItems,omitempty"`             // section 5.11
	UniqueItems          bool             `json:"uniqueItems,omitempty"`          // section 5.12
	MaxProperties        int              `json:"maxProperties,omitempty"`        // section 5.13
	MinProperties        int              `json:"minProperties,omitempty"`        // section 5.14
	Required             []string         `json:"required,omitempty"`             // section 5.15
	Properties           map[string]*Type `json:"properties,omitempty"`           // section 5.16
	PatternProperties    map[string]*Type `json:"patternProperties,omitempty"`    // section 5.17
	AdditionalProperties json.RawMessage  `json:"additionalProperties,omitempty"` // section 5.18
	Dependencies         map[string]*Type `json:"dependencies,omitempty"`         // section 5.19
	Enum                 []interface{}    `json:"enum,omitempty"`                 // section 5.20
	Type                 string           `json:"bsonType,omitempty"`             // section 5.21
	AllOf                []*Type          `json:"allOf,omitempty"`                // section 5.22
	AnyOf                []*Type          `json:"anyOf,omitempty"`                // section 5.23
	OneOf                []*Type          `json:"oneOf,omitempty"`                // section 5.24
	Not                  *Type            `json:"not,omitempty"`                  // section 5.25
	Definitions          Definitions      `json:"definitions,omitempty"`          // section 5.26
	// RFC draft-wright-json-schema-validation-00, section 6, 7
	Title       string      `json:"title,omitempty"`       // section 6.1
	Description string      `json:"description,omitempty"` // section 6.1
	Default     interface{} `json:"default,omitempty"`     // section 6.2
	Format      string      `json:"format,omitempty"`      // section 7
	// RFC draft-wright-json-schema-hyperschema-00, section 4
	Media          *Type  `json:"media,omitempty"`          // section 4.3
	BinaryEncoding string `json:"binaryEncoding,omitempty"` // section 4.3
}

// Reflect reflects to Schema from a value using the default Reflector
func Reflect(v interface{}) *Schema {
	return ReflectFromType(reflect.TypeOf(v))
}

// ReflectFromType generates root schema using the default Reflector
func ReflectFromType(t reflect.Type) *Schema {
	r := &Reflector{}
	return r.ReflectFromType(t)
}

// A Reflector reflects values into a Schema.
type Reflector struct {
	// AllowAdditionalProperties will cause the Reflector to generate a schema
	// with additionalProperties to 'true' for all struct types. This means
	// the presence of additional keys in JSON objects will not cause validation
	// to fail. Note said additional keys will simply be dropped when the
	// validated JSON is unmarshaled.
	AllowAdditionalProperties bool

	// RequiredFromJSONSchemaTags will cause the Reflector to generate a schema
	// that requires any key tagged with `jsonschema:required`, overriding the
	// default of requiring any key *not* tagged with `json:,omitempty`.
	RequiredFromJSONSchemaTags bool

	// ExpandedStruct will cause the toplevel definitions of the schema not
	// be referenced itself to a definition.
	ExpandedStruct bool
}

// Reflect reflects to Schema from a value.
func (r *Reflector) Reflect(v interface{}) *Schema {
	return r.ReflectFromType(reflect.TypeOf(v))
}

// ReflectFromType generates root schema
func (r *Reflector) ReflectFromType(t reflect.Type) *Schema {
	// 创建一个新的根 schema 对象
	st := &Type{
		Type:                 "object",
		Properties:           map[string]*Type{},
		AdditionalProperties: []byte("true"), // MongoDB 默认允许额外字段
	}

	// 直接处理字段,而不是使用引用
	r.reflectStructFields(st, nil, t)

	// MongoDB特定处理：处理id/_id问题
	r.fixMongoIssues(st)

	// 包装并返回 schema
	return &Schema{
		Type: st,
	}
}

// fixMongoIssues 处理MongoDB特定的问题，例如id和_id的映射关系
func (r *Reflector) fixMongoIssues(st *Type) {
	// 如果存在id属性，将其转为_id属性
	if idProp, exists := st.Properties["id"]; exists {
		st.Properties["_id"] = idProp
		delete(st.Properties, "id")
	}

	// 在required列表中，将id替换为_id
	for i, field := range st.Required {
		if field == "id" {
			st.Required[i] = "_id"
		}
	}
}

// Definitions hold schema definitions.
// http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.26
// RFC draft-wright-json-schema-validation-00, section 5.26
type Definitions map[string]*Type

// Available Go defined types for JSON Schema Validation.
// RFC draft-wright-json-schema-validation-00, section 7.3
var (
	timeType = reflect.TypeOf(time.Time{}) // date-time RFC section 7.3.1
	ipType   = reflect.TypeOf(net.IP{})    // ipv4 and ipv6 RFC section 7.3.4, 7.3.5
	uriType  = reflect.TypeOf(url.URL{})   // uri RFC section 7.3.6
)

// Byte slices will be encoded as base64
var byteSliceType = reflect.TypeOf([]byte(nil))

// Go code generated from protobuf enum types should fulfil this interface.
type protoEnum interface {
	EnumDescriptor() ([]byte, []int)
}

var protoEnumType = reflect.TypeOf((*protoEnum)(nil)).Elem()

// reflectTypeToSchema 转换 Go 类型到 MongoDB schema 类型
func (r *Reflector) reflectTypeToSchema(definitions Definitions, t reflect.Type) *Type {
	// 添加对primitive.ObjectID类型的直接支持
	if t.String() == "primitive.ObjectID" {
		return &Type{Type: "objectId"}
	}

	switch t.Kind() {
	case reflect.Struct:
		switch t {
		case timeType:
			return &Type{Type: "date"}
		case uriType:
			return &Type{Type: "string", Format: "uri"}
		default:
			// 直接展开结构体
			st := &Type{
				Type:                 "object",
				Properties:           map[string]*Type{},
				AdditionalProperties: []byte("true"),
			}
			r.reflectStructFields(st, definitions, t)
			return st
		}

	case reflect.Map:
		return &Type{
			Type:                 "object",
			AdditionalProperties: []byte("true"),
		}

	case reflect.Slice:
		switch t {
		case byteSliceType:
			return &Type{Type: "binData"}
		default:
			// 如果数组元素是结构体，直接内联展开
			elemType := t.Elem()
			if elemType.Kind() == reflect.Struct && elemType != timeType && elemType != uriType {
				return &Type{
					Type: "array",
					Items: &Type{
						Type:                 "object",
						Properties:           map[string]*Type{},
						AdditionalProperties: []byte("true"),
						Required:             []string{},
					},
				}
			}
			return &Type{
				Type:  "array",
				Items: r.reflectTypeToSchema(definitions, elemType),
			}
		}

	case reflect.Interface:
		return &Type{
			Type:                 "object",
			AdditionalProperties: []byte("true"),
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return &Type{Type: "int"}

	case reflect.Int64, reflect.Uint64:
		return &Type{Type: "long"}

	case reflect.Float64:
		return &Type{Type: "double"}

	case reflect.Float32:
		return &Type{Type: "decimal"}

	case reflect.Bool:
		return &Type{Type: "bool"}

	case reflect.String:
		return &Type{Type: "string"}

	case reflect.Ptr:
		return r.reflectTypeToSchema(definitions, t.Elem())

	case reflect.Array:
		if t == reflect.TypeOf([12]byte{}) {
			return &Type{Type: "objectId"}
		}
		return &Type{
			Type:  "array",
			Items: r.reflectTypeToSchema(definitions, t.Elem()),
		}
	}

	// 默认作为对象处理
	return &Type{
		Type:                 "object",
		AdditionalProperties: []byte("true"),
	}
}

// Refects a struct to a JSON Schema type.
func (r *Reflector) reflectStruct(definitions Definitions, t reflect.Type) *Type {
	st := &Type{
		Type:                 "object",
		Properties:           map[string]*Type{},
		AdditionalProperties: []byte("true"), // MongoDB 默认允许额外字段
	}

	// 直接内联字段，不使用引用
	r.reflectStructFields(st, definitions, t)
	return st
}

// reflectStructFields 递归处理结构体字段
func (r *Reflector) reflectStructFields(st *Type, definitions Definitions, t reflect.Type) {
	// 处理指针类型
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// 遍历所有字段
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		// 处理匿名嵌入字段
		if f.Anonymous && f.PkgPath == "" {
			r.reflectStructFields(st, definitions, f.Type)
			continue
		}

		// 获取字段名和是否必需
		name, required := r.reflectFieldName(f)
		if name == "" {
			continue
		}

		// 获取字段的类型 schema
		property := r.reflectTypeToSchema(definitions, f.Type)

		// 处理字段的标签
		property.structKeywordsFromTags(f)

		// 添加到属性映射
		st.Properties[name] = property

		// 如果是必需字段,添加到必需列表
		if required {
			st.Required = append(st.Required, name)
		}
	}
}

func (t *Type) structKeywordsFromTags(f reflect.StructField) {
	tags := strings.Split(f.Tag.Get("jsonschema"), ",")

	// 首先检查是否有oid标记，这比类型检查优先级更高
	for _, tag := range tags {
		if tag == "oid" {
			t.Type = "objectId"
			return // 一旦设置为objectId，就不需要继续处理其他类型相关的标签
		}
	}

	switch t.Type {
	case "string":
		t.stringKeywords(tags)
	case "double":
		t.numbericKeywords(tags)
	case "decimal":
		t.numbericKeywords(tags)
	case "long":
		t.numbericKeywords(tags)
	case "int":
		t.numbericKeywords(tags)
	case "array":
		t.arrayKeywords(tags)
	}
}

// read struct tags for string type keyworks
func (t *Type) stringKeywords(tags []string) {
	for _, tag := range tags {
		nameValue := strings.Split(tag, "=")
		if len(nameValue) == 2 {
			name, val := nameValue[0], nameValue[1]
			switch name {
			case "minLength":
				i, _ := strconv.Atoi(val)
				t.MinLength = i
			case "maxLength":
				i, _ := strconv.Atoi(val)
				t.MaxLength = i
			case "format":
				switch val {
				case "date-time", "email", "hostname", "ipv4", "ipv6", "uri":
					t.Format = val
					break
				}
			case "enum":
				ems := strings.Split(val, "|")
				for _, v := range ems {
					t.Enum = append(t.Enum, v)
				}
			case "description":
				t.Description = val
			}
		}
	}
}

// read struct tags for numberic type keyworks
func (t *Type) numbericKeywords(tags []string) {
	for _, tag := range tags {
		nameValue := strings.Split(tag, "=")
		if len(nameValue) == 2 {
			name, val := nameValue[0], nameValue[1]
			switch name {
			case "multipleOf":
				i, _ := strconv.Atoi(val)
				t.MultipleOf = i
			case "minimum":
				i, _ := strconv.Atoi(val)
				t.Minimum = &i
			case "maximum":
				i, _ := strconv.Atoi(val)
				t.Maximum = &i
			case "exclusiveMaximum":
				b, _ := strconv.ParseBool(val)
				t.ExclusiveMaximum = b
			case "exclusiveMinimum":
				b, _ := strconv.ParseBool(val)
				t.ExclusiveMinimum = b
			case "description":
				t.Description = val
			}
		}
	}
}

// read struct tags for object type keyworks
// func (t *Type) objectKeywords(tags []string) {
//     for _, tag := range tags{
//         nameValue := strings.Split(tag, "=")
//         name, val := nameValue[0], nameValue[1]
//         switch name{
//             case "dependencies":
//                 t.Dependencies = val
//                 break;
//             case "patternProperties":
//                 t.PatternProperties = val
//                 break;
//         }
//     }
// }

// read struct tags for array type keyworks
func (t *Type) arrayKeywords(tags []string) {
	for _, tag := range tags {
		nameValue := strings.Split(tag, "=")
		if len(nameValue) == 2 {
			name, val := nameValue[0], nameValue[1]
			switch name {
			case "minItems":
				i, _ := strconv.Atoi(val)
				t.MinItems = i
			case "maxItems":
				i, _ := strconv.Atoi(val)
				t.MaxItems = i
			case "uniqueItems":
				t.UniqueItems = true
			}
		}
		if tag == "oids" {
			t.Items.Type = "objectId"
		}
	}
}

func requiredFromJSONTags(tags []string) bool {
	if ignoredByJSONTags(tags) {
		return false
	}

	for _, tag := range tags[1:] {
		if tag == "omitempty" {
			return false
		}
	}
	return true
}

func requiredFromJSONSchemaTags(tags []string) bool {
	if ignoredByJSONSchemaTags(tags) {
		return false
	}
	for _, tag := range tags {
		if tag == "required" {
			return true
		}
	}
	return false
}

func ignoredByJSONTags(tags []string) bool {
	return tags[0] == "-"
}

func ignoredByJSONSchemaTags(tags []string) bool {
	return tags[0] == "-"
}

// reflectFieldName 获取字段的 JSON 名称和是否必需
func (r *Reflector) reflectFieldName(f reflect.StructField) (string, bool) {
	if f.PkgPath != "" { // 未导出字段
		return "", false
	}

	jsonTags := strings.Split(f.Tag.Get("json"), ",")
	if ignoredByJSONTags(jsonTags) {
		return "", false
	}

	jsonSchemaTags := strings.Split(f.Tag.Get("jsonschema"), ",")
	if ignoredByJSONSchemaTags(jsonSchemaTags) {
		return "", false
	}

	name := f.Name
	required := requiredFromJSONTags(jsonTags)

	if r.RequiredFromJSONSchemaTags {
		required = requiredFromJSONSchemaTags(jsonSchemaTags)
	}

	// 首先从JSON标签获取名称
	if jsonTags[0] != "" {
		name = jsonTags[0]
	}

	// 从BSON标签处理_id映射
	bsonTags := strings.Split(f.Tag.Get("bson"), ",")
	if len(bsonTags) > 0 && bsonTags[0] == "_id" {
		// 如果BSON标签是_id，确保在Schema中使用id
		if name == "_id" {
			name = "id"
		}
	}

	return name, required
}
