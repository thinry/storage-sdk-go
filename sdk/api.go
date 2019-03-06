package sdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

const (
	ERROR_AUTH_CHECK_TOKEN_FAIL    = 20001
	ERROR_AUTH_CHECK_TOKEN_TIMEOUT = 20002
	ERROR_AUTH_TOKEN               = 20003
	ERROR_AUTH                     = 20004
)

// API contains fields to communicate with the go-oss-aio
type API struct {
	host  string
	token string
}

// New returns client for Ceph RADOS Gateway
func NewApi(host, userName, password string) (*API, error) {
	if host == "" {
		return nil, fmt.Errorf("host must be not nil")
	}

	client := API{host, ""}

	token, err := client.GetToken(&GetToken{UserName: userName, Password: password})
	if err != nil {
		return nil, err
	}
	client.token = token.Token

	return &client, nil
}

func String(v string) *string {
	return &v
}
func Int64(v int64) *int64 {
	return &v
}

type ErrorToken struct {
	Code    int
	Message string
	AuthUrl string
}

func (api *API) PostJson(url string, input interface{}, ret interface{}) error {

	return api.execute("POST", "application/json;charset=utf-8", url, input, ret)
}

func (api *API) DeleteJson(url string, input interface{}, ret interface{}) error {

	return api.execute("DELETE", "application/json;charset=utf-8", url, input, ret)
}
func (api *API) PutJson(url string, input interface{}, ret interface{}) error {
	return api.execute("PUT", "application/json;charset=utf-8", url, input, ret)
}

func (api *API) GetJson(apiUrl string, ret interface{}) error {

	client := &http.Client{}

	req, _ := http.NewRequest("GET", api.host+apiUrl, nil)
	if api.token != "" {
		req.Header.Add("token", api.token)
	}

	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		var tokenErr ErrorToken
		if err = json.Unmarshal(body, &tokenErr); err != nil {
			return errors.New(string(body))
		}
		if tokenErr.Code == ERROR_AUTH_CHECK_TOKEN_FAIL {
			return errors.New("parse token error ")
		}
		if tokenErr.Code == ERROR_AUTH_CHECK_TOKEN_TIMEOUT {
			return errors.New("token expired ,please new client again")
		}
		if tokenErr.Code == ERROR_AUTH {
			return errors.New("token not exist")
		}
		return errors.New(string(body))
	}
	if resp.StatusCode >= 400 {
		return errors.New(string(body))
	}
	if err = json.Unmarshal(body, &ret); err != nil {
		return err
	}
	return err

	err = errors.New("param to json error")
	return err
}

func (api *API) PostFile(apiUrl, file string, ret interface{}) error {

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("file", file)

	if err != nil {
		fmt.Println("error  bodyWriter.CreateFormFile")
		return err
	}
	of, err := os.Open(file)
	defer of.Close()
	_, err = io.Copy(fileWriter, of)
	if err != nil {
		fmt.Println("error  io.Copy")
		return err
	}
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	client := &http.Client{}

	req, _ := http.NewRequest("POST", api.host+apiUrl, bodyBuf)
	if api.token != "" {

		req.Header.Add("token", api.token)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)

	if err != nil {

		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		var tokenErr ErrorToken
		if err = json.Unmarshal(body, &tokenErr); err != nil {
			return errors.New(string(body))
		}
		if tokenErr.Code == ERROR_AUTH_CHECK_TOKEN_FAIL {
			return errors.New("token auth fail ,parse token error")
		}
		if tokenErr.Code == ERROR_AUTH_CHECK_TOKEN_TIMEOUT {
			return errors.New("token expired ,please new client again")
		}
		if tokenErr.Code == ERROR_AUTH {
			return errors.New("token not exist")
		}
		return errors.New(string(body))
	}
	if resp.StatusCode >= 400 {
		return errors.New(string(body))
	}
	if err = json.Unmarshal(body, &ret); err != nil {
		return err
	}
	return err

	err = errors.New("param to json error")
	return err
}
func (api *API) execute(method, contentType, apiUrl string, input interface{}, ret interface{}) error {
	var reqData *bytes.Buffer

	if input != nil {
		bs, err := json.Marshal(input)
		if err != nil {

			return errors.New("param to json error")
		}
		reqData = bytes.NewBuffer([]byte(bs))
	} else {
		reqData = &bytes.Buffer{}
	}

	client := &http.Client{}

	req, _ := http.NewRequest(method, api.host+apiUrl, reqData)
	if api.token != "" {

		req.Header.Add("token", api.token)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		var tokenErr ErrorToken
		if err = json.Unmarshal(body, &tokenErr); err != nil {
			return errors.New(string(body))
		}
		if tokenErr.Code == ERROR_AUTH_CHECK_TOKEN_FAIL {
			return errors.New("token auth fail ,parse token error")
		}
		if tokenErr.Code == ERROR_AUTH_CHECK_TOKEN_TIMEOUT {
			return errors.New("token expired ,please new client again")
		}
		if tokenErr.Code == ERROR_AUTH {
			return errors.New("token not exist")
		}
		return errors.New(string(body))
	}

	if resp.StatusCode >= 400 {
		return errors.New(string(body))
	}
	if err = json.Unmarshal(body, &ret); err != nil {
		return err
	}
	return err

	err = errors.New("param to json error")
	return err
}

type Message struct {
	MessageInfo string `json:"message"`
}

// GetToken request
type GetToken struct {
	Password string `json:"password"`
	UserName string `json:"userName"`
}

//GetToken response
type Token struct {
	//token
	Token string
}

// Get token by user name and password
// @Password
// @UserName
func (api *API) GetToken(conf *GetToken) (*Token, error) {
	if conf.Password == "" {
		return nil, errors.New("password field is required")
	}
	if conf.UserName == "" {
		return nil, errors.New("UserName field is required")
	}
	var ret Token
	err := api.PostJson("/token", conf, &ret)
	return &ret, err
}

type ListObjectsOutput struct {
	_ struct{} `type:"structure"`

	CommonPrefixes []*CommonPrefix `type:"list" flattened:"true"`

	Contents []*Object `type:"list" flattened:"true"`

	Delimiter *string `type:"string"`

	// Encoding type used by Amazon S3 to encode object keys in the response.
	EncodingType *string `type:"string" enum:"EncodingType"`

	// A flag that indicates whether or not Amazon S3 returned all of the results
	// that satisfied the search criteria.
	IsTruncated *bool `type:"boolean"`

	Marker *string `type:"string"`

	MaxKeys *int64 `type:"integer"`

	Name *string `type:"string"`

	// When response is truncated (the IsTruncated element value in the response
	// is true), you can use the key name in this field as marker in the subsequent
	// request to get next set of objects. Amazon S3 lists objects in alphabetical
	// order Note: This element is returned only if you have delimiter request parameter
	// specified. If response does not include the NextMaker and it is truncated,
	// you can use the value of the last Key in the response as the marker in the
	// subsequent request to get the next set of object keys.
	NextMarker *string `type:"string"`

	Prefix *string `type:"string"`
}

type CommonPrefix struct {
	_ struct{} `type:"structure"`

	Prefix *string `type:"string"`
}

type Object struct {
	_ struct{} `type:"structure"`

	ETag *string `type:"string"`

	Key *string `min:"1" type:"string"`

	LastModified *time.Time `type:"timestamp"`

	Owner *Owner `type:"structure"`

	Size *int64 `type:"integer"`

	// The class of storage used to store the object.
	StorageClass *string `type:"string" enum:"ObjectStorageClass"`
}

//@bucketName required true
//@marker required false
//@prefix required false
//@delimiter required false
//@maxKeys required false
func (api *API) ListObject(bucketName, marker, prefix, delimiter, maxKeys string) (*ListObjectsOutput, error) {

	var ret ListObjectsOutput
	err := api.GetJson(fmt.Sprintf("/api/v1/buckets/%s/objects?marker=%s&prefix=%s&delimiter=%s&maxKeys=%s", bucketName, marker, prefix, delimiter, maxKeys), &ret)
	return &ret, err
}

// KeyConfig
type KeyConfig struct {
	// The user ID to receive the new key
	UserId string `url:"uid,ifStringIsNotEmpty" required:"false"`
	// The subuser ID to receive the new key
	SubUser string `url:"subuser,ifStringIsNotEmpty" required:"false"`
	// Key type to be generated, options are: swift, s3 (default)
	KeyType string `url:"key-type,ifStringIsNotEmpty" required:"false"`
	// Specify the access key
	AccessKey string `url:"access-key,ifStringIsNotEmpty" required:"true"`
	// Specify secret key
	SecretKey string `url:"secret-key,ifStringIsNotEmpty" required:"false"`
	// Generate a new key pair and add to the existing keyring
	GenerateSecret bool `url:"generate-secret,ifBoolIsTrue" `
}

// Create user key
// Permission demands super user
// CreateKey creates a new key. If a subuser is specified then by default created keys will be swift type.
// If only one of access-key or secret-key is provided the committed key will be automatically generated,
// that is if only secret-key is specified then access-key will be automatically generated.
// By default, a generated key is added to the keyring without replacing an existing key pair.
// If access-key is specified and refers to an existing key owned by the user then it will be modified.
// The response is a container listing all keys of the same type as the key created.
// Note that when creating a swift key, specifying the option access-key will have no effect.
// Additionally, only one swift key may be held by each user or subuser.
// @UserId
func (api *API) CreateUserKeyForUser(conf *KeyConfig) (*Message, error) {
	if conf.UserId == "" {
		return nil, errors.New("UserId field is required")
	}
	var ret Message
	err := api.PostJson("/api/v1/admin/users/keys", conf, &ret)
	return &ret, err
}

// Create user key
// CreateKey creates a new key. If a subuser is specified then by default created keys will be swift type.
// If only one of access-key or secret-key is provided the committed key will be automatically generated,
// that is if only secret-key is specified then access-key will be automatically generated.
// By default, a generated key is added to the keyring without replacing an existing key pair.
// If access-key is specified and refers to an existing key owned by the user then it will be modified.
// The response is a container listing all keys of the same type as the key created.
// Note that when creating a swift key, specifying the option access-key will have no effect.
// Additionally, only one swift key may be held by each user or subuser.
func (api *API) CreateUserKey(conf *KeyConfig) (*Message, error) {
	var ret Message
	err := api.PostJson("/api/v1/keys", conf, &ret)
	return &ret, err
}

type User struct {
	ID        string `gorm:"primary_key" json:"id" sql:"type:varchar(50)"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
	Uid       string    `json:"uid" sql:"type:varchar(100);unique;not null"` //ceph user uid
	UserName  string    `json:"user_name" sql:"type:varchar(100);not null"`  //user name
	Password  string    `json:"password" sql:"type:varchar(100);not null"`   //user password
	RoleId    string    `json:"role_id"  sql:"type:varchar(20);not null"`    //roleId
	OpenId    string    `json:"open_id" sql:"type:varchar(50)"`              //oauth open id
	NikeName  string    `json:"nike_name" sql:"type:varchar(50);"`           //auth user name
	CreateBy  string    `sql:"type:varchar(50)"`
	UserKey   []UserKey `json:"user_key" `
}
type UserKey struct {
	ID        string `gorm:"primary_key" json:"id" sql:"type:varchar(50)"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
	UserId    string `json:"user_id" gorm:"index" sql:"type:varchar(50);not null"`
	AccessKey string `json:"access_key,omitempty" sql:"type:varchar(50);not null"`
	SecretKey string `json:"secret_key" sql:"type:varchar(100);not null"`
	CreateBy  string `sql:"type:varchar(50)"`
}

// user info
func (api *API) GetUserByToken() (*User, error) {
	var ret User
	err := api.GetJson("/api/v1/users", &ret)
	return &ret, err
}

type UserList struct {
	Users      []User
	Total      int
	PageOffset int
	PageSize   int
	Page       int
}

// user info
//@userName required false
//@page required false
//@pageSize required false
func (api *API) GetUsers(userName *string, page, pageSize *int) (*UserList, error) {
	var ret UserList
	err := api.GetJson(fmt.Sprintf("/api/v1/admin/users?userName=%s&page=%d&pageSize=%d", userName, page, pageSize), &ret)
	return &ret, err
}

// Quotas represents the reponse of quotas requests
type Quotas struct {
	BucketQuota struct {
		Enabled    bool `json:"enabled"`
		MaxObjects int  `json:"max_objects"`
		MaxSizeKb  int  `json:"max_size_kb"`
	} `json:"bucket_quota"`
	UserQuota struct {
		Enabled    bool `json:"enabled"`
		MaxObjects int  `json:"max_objects"`
		MaxSizeKb  int  `json:"max_size_kb"`
	} `json:"user_quota"`
}

// GetQuotas
func (api *API) GetQuotas(userId *string) (*Quotas, error) {
	var ret Quotas
	err := api.GetJson(fmt.Sprintf("/api/v1/admin/users/%s/quotas", *userId), &ret)
	return &ret, err
}

type QuotaParam struct {
	// The max-objects setting allows you to specify the maximum number of objects. A negative value disables this setting.
	MaxObjects string `url:"max-objects,ifStringIsNotEmpty" json:"maxObjects"`
	// The max-size-kb option allows you to specify a quota for the maximum number of bytes. A negative value disables this setting
	MaxSizeKB string `url:"max-size-kb,ifStringIsNotEmpty" json:"maxSizeKb"`
	// The enabled option enables the quotas
	Enabled string `url:"enabled,ifStringIsNotEmpty" json:"enabled"`
	// The quota-type option sets the scope for the quota. The options are bucket and user.
	QuotaType string `url:"quota-type,ifStringIsNotEmpty" json:"quotaType" required:"true"`
}

// PutQuotas
func (api *API) PutQuotas(userId string, input *QuotaParam) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/admin/users/%s/quotas", userId), input, &ret)
	return &ret, err
}

type Stats struct {
	Bucket      string `json:"bucket"`
	BucketQuota struct {
		Enabled    bool `json:"enabled"`
		MaxObjects int  `json:"max_objects"`
		MaxSizeKb  int  `json:"max_size_kb"`
	} `json:"bucket_quota"`
	ID        string `json:"id"`
	IndexPool string `json:"index_pool"`
	Marker    string `json:"marker"`
	MasterVer string `json:"master_ver"`
	MaxMarker string `json:"max_marker"`
	Mtime     string `json:"mtime"`
	Owner     string `json:"owner"`
	Pool      string `json:"pool"`
	Usage     struct {
		RgwMain struct {
			NumObjects   int `json:"num_objects"`
			SizeKb       int `json:"size_kb"`
			SizeKbActual int `json:"size_kb_actual"`
		} `json:"rgw.main"`
	} `json:"usage"`
	Ver string `json:"ver"`
}

// GetBucketInfo
func (api *API) GetBucketInfo(bucketName string) (*Stats, error) {
	var ret Stats
	err := api.GetJson(fmt.Sprintf("/api/v1/buckets/%s/info", bucketName), &ret)
	return &ret, err
}

type CreateBucketInput struct {
	_ struct{} `type:"structure" payload:"CreateBucketConfiguration"`

	// The canned ACL to apply to the bucket.
	ACL *string `location:"header" locationName:"x-amz-acl" type:"string" enum:"BucketCannedACL"`

	// Bucket is a required field
	Bucket *string `location:"uri" locationName:"Bucket" type:"string" required:"true"`

	CreateBucketConfiguration *CreateBucketConfiguration `locationName:"CreateBucketConfiguration" type:"structure" xmlURI:"http://s3.amazonaws.com/doc/2006-03-01/"`

	// Allows grantee the read, write, read ACP, and write ACP permissions on the
	// bucket.
	GrantFullControl *string `location:"header" locationName:"x-amz-grant-full-control" type:"string"`

	// Allows grantee to list the objects in the bucket.
	GrantRead *string `location:"header" locationName:"x-amz-grant-read" type:"string"`

	// Allows grantee to read the bucket ACL.
	GrantReadACP *string `location:"header" locationName:"x-amz-grant-read-acp" type:"string"`

	// Allows grantee to create, overwrite, and delete any object in the bucket.
	GrantWrite *string `location:"header" locationName:"x-amz-grant-write" type:"string"`

	// Allows grantee to write the ACL for the applicable bucket.
	GrantWriteACP *string `location:"header" locationName:"x-amz-grant-write-acp" type:"string"`

	// Specifies whether you want S3 Object Lock to be enabled for the new bucket.
	ObjectLockEnabledForBucket *bool `location:"header" locationName:"x-amz-bucket-object-lock-enabled" type:"boolean"`
}

type CreateBucketConfiguration struct {
	_ struct{} `type:"structure"`

	// Specifies the region where the bucket will be created. If you don't specify
	// a region, the bucket will be created in US Standard.
	LocationConstraint *string `type:"string" enum:"BucketLocationConstraint"`
}

// AddBuckets
func (api *API) CreateBuckets(input *CreateBucketInput) (*Message, error) {
	var ret Message
	err := api.PostJson("/api/v1/buckets", input, &ret)
	return &ret, err
}

type GetBucketAclOutput struct {
	_ struct{} `type:"structure"`

	// A list of grants.
	Grants []*Grant `locationName:"AccessControlList" locationNameList:"Grant" type:"list"`

	Owner *Owner `type:"structure"`
}
type AccessControlPolicy struct {
	_ struct{} `type:"structure"`

	// A list of grants.
	Grants []*Grant `locationName:"AccessControlList" locationNameList:"Grant" type:"list"`

	Owner *Owner `type:"structure"`
}
type Grant struct {
	_ struct{} `type:"structure"`

	Grantee *Grantee `type:"structure" xmlPrefix:"xsi" xmlURI:"http://www.w3.org/2001/XMLSchema-instance"`

	// Specifies the permission given to the grantee.
	Permission *string `type:"string" enum:"Permission"`
}
type Grantee struct {
	_ struct{} `type:"structure" xmlPrefix:"xsi" xmlURI:"http://www.w3.org/2001/XMLSchema-instance"`

	// Screen name of the grantee.
	DisplayName *string `type:"string"`

	// Email address of the grantee.
	EmailAddress *string `type:"string"`

	// The canonical user ID of the grantee.
	ID *string `type:"string"`

	// Type of grantee
	//
	// Type is a required field
	Type *string `locationName:"xsi:type" type:"string" xmlAttribute:"true" required:"true" enum:"Type"`

	// URI of the grantee group.
	URI *string `type:"string"`
}
type Owner struct {
	_ struct{} `type:"structure"`

	DisplayName *string `type:"string"`

	ID *string `type:"string"`
}

// GetBucketAcl
func (api *API) GetBucketAcl(bucketName string) (*GetBucketAclOutput, error) {
	var ret GetBucketAclOutput
	err := api.GetJson(fmt.Sprintf("/api/v1/buckets/%s/acl", bucketName), &ret)
	return &ret, err
}

type PutBucketAclOutputParam struct {
	AccessControlPolicy *AccessControlPolicy `json:"accessControlPolicy"`
	//Valid Values: private | public-read | public-read-write | authenticated-read
	Acl string `json:"acl"`
}

//PutObjectAcl
func (api *API) PutObjectAcl(input *PutBucketAclOutputParam, bucketName, objectName string) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/buckets/%s/object/acl?objectName=%s", bucketName, objectName), input, &ret)
	return &ret, err
}

// PutBucketAcl
func (api *API) PutBucketAcl(input *PutBucketAclOutputParam, bucketName string) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/buckets/%s/acl", bucketName), input, &ret)
	return &ret, err
}

type PutObjectInput struct {
	//ObjectName
	ObjectName string `json:"objectName"`
	//file path
	FilePath string
}

type PutObjectOutput struct {
	_ struct{} `type:"structure"`

	// Entity tag for the uploaded object.
	ETag *string `location:"header" locationName:"ETag" type:"string"`

	// If the object expiration is configured, this will contain the expiration
	// date (expiry-date) and rule ID (rule-id). The value of rule-id is URL encoded.
	Expiration *string `location:"header" locationName:"x-amz-expiration" type:"string"`

	// If present, indicates that the requester was successfully charged for the
	// request.
	RequestCharged *string `location:"header" locationName:"x-amz-request-charged" type:"string" enum:"RequestCharged"`

	// If server-side encryption with a customer-provided encryption key was requested,
	// the response will include this header confirming the encryption algorithm
	// used.
	SSECustomerAlgorithm *string `location:"header" locationName:"x-amz-server-side-encryption-customer-algorithm" type:"string"`

	// If server-side encryption with a customer-provided encryption key was requested,
	// the response will include this header to provide round trip message integrity
	// verification of the customer-provided encryption key.
	SSECustomerKeyMD5 *string `location:"header" locationName:"x-amz-server-side-encryption-customer-key-MD5" type:"string"`

	// If present, specifies the ID of the AWS Key Management Service (KMS) master
	// encryption key that was used for the object.
	SSEKMSKeyId *string `location:"header" locationName:"x-amz-server-side-encryption-aws-kms-key-id" type:"string" sensitive:"true"`

	// The Server-side encryption algorithm used when storing this object in S3
	// (e.g., AES256, aws:kms).
	ServerSideEncryption *string `location:"header" locationName:"x-amz-server-side-encryption" type:"string" enum:"ServerSideEncryption"`

	// Version of the object.
	VersionId *string `location:"header" locationName:"x-amz-version-id" type:"string"`
}

func (api *API) PutObject(bucketName string, input *PutObjectInput) (*PutObjectOutput, error) {
	var ret PutObjectOutput
	oName := base64.URLEncoding.EncodeToString([]byte(input.ObjectName))

	err := api.PostFile(fmt.Sprintf("/api/v1/buckets/%s/object/api?objectName="+oName, bucketName), input.FilePath, &ret)
	return &ret, err
}

type ObjectCopyParam struct {
	//Copy source
	CopySource string `json:"copySource" minLength:"1" `
	//ObjectName
	ObjectName string `json:"objectName"`
}

func (api *API) CopyObject(bucketName string, input *ObjectCopyParam) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/buckets/%s/object", bucketName), input, &ret)
	return &ret, err
}

type ObjectRenameParam struct {
	//Copy source key
	CopySource string `json:"copySource" minLength:"1" `
	//new object key
	ObjectName string `json:"objectName"`
}

// @description The previous version number is lost after renaming, and the old object is deleted, ensuring that the new objectName entered is the same as the source
func (api *API) RenameObject(bucketName string, input *ObjectRenameParam) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/buckets/%s/object/name", bucketName), input, &ret)
	return &ret, err
}

type HeadObjectParam struct {

	// Return the object only if its entity tag (ETag) is the same as the one specified,
	// otherwise return a 412 (precondition failed).
	IfMatch *string `location:"header" locationName:"If-Match" type:"string"`

	// Return the object only if it has been modified since the specified time,
	// otherwise return a 304 (not modified).
	IfModifiedSince *time.Time `location:"header" locationName:"If-Modified-Since" type:"timestamp"`

	// Return the object only if its entity tag (ETag) is different from the one
	// specified, otherwise return a 304 (not modified).
	IfNoneMatch *string `location:"header" locationName:"If-None-Match" type:"string"`

	// Return the object only if it has not been modified since the specified time,
	// otherwise return a 412 (precondition failed).
	IfUnmodifiedSince *time.Time `location:"header" locationName:"If-Unmodified-Since" type:"timestamp"`

	// Key is a required field
	Key *string `location:"uri" locationName:"Key" min:"1" type:"string" required:"true" json:"key" form:"key"`

	// Part number of the object being read. This is a positive integer between
	// 1 and 10,000. Effectively performs a 'ranged' HEAD request for the part specified.
	// Useful querying about the size of the part and the number of parts in this
	// object.
	PartNumber *int64 `location:"querystring" locationName:"partNumber" type:"integer"`

	// Downloads the specified range bytes of an object. For more information about
	// the HTTP Range header, go to http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35.
	Range *string `location:"header" locationName:"Range" type:"string"`

	// Confirms that the requester knows that she or he will be charged for the
	// request. Bucket owners need not specify this parameter in their requests.
	// Documentation on downloading objects from requester pays buckets can be found
	// at http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html
	RequestPayer *string `location:"header" locationName:"x-amz-request-payer" type:"string" enum:"RequestPayer"`

	// Specifies the algorithm to use to when encrypting the object (e.g., AES256).
	SSECustomerAlgorithm *string `location:"header" locationName:"x-amz-server-side-encryption-customer-algorithm" type:"string"`

	// Specifies the customer-provided encryption key for Amazon S3 to use in encrypting
	// data. This value is used to store the object and then it is discarded; Amazon
	// does not store the encryption key. The key must be appropriate for use with
	// the algorithm specified in the x-amz-server-side​-encryption​-customer-algorithm
	// header.
	SSECustomerKey *string `location:"header" locationName:"x-amz-server-side-encryption-customer-key" type:"string" sensitive:"true"`

	// Specifies the 128-bit MD5 digest of the encryption key according to RFC 1321.
	// Amazon S3 uses this header for a message integrity check to ensure the encryption
	// key was transmitted without error.
	SSECustomerKeyMD5 *string `location:"header" locationName:"x-amz-server-side-encryption-customer-key-MD5" type:"string"`

	// VersionId used to reference a specific version of the object.
	VersionId *string `location:"querystring" locationName:"versionId" type:"string"`
}
type ObjectInfoResult struct {
	_ struct{} `type:"structure"`

	AcceptRanges *string `location:"header" locationName:"accept-ranges" type:"string"`

	// Specifies caching behavior along the request/reply chain.
	CacheControl *string `location:"header" locationName:"Cache-Control" type:"string"`

	// Specifies presentational information for the object.
	ContentDisposition *string `location:"header" locationName:"Content-Disposition" type:"string"`

	// Specifies what content encodings have been applied to the object and thus
	// what decoding mechanisms must be applied to obtain the media-type referenced
	// by the Content-Type header field.
	ContentEncoding *string `location:"header" locationName:"Content-Encoding" type:"string"`

	// The language the content is in.
	ContentLanguage *string `location:"header" locationName:"Content-Language" type:"string"`

	// Size of the body in bytes.
	ContentLength *int64 `location:"header" locationName:"Content-Length" type:"long"`

	// A standard MIME type describing the format of the object data.
	ContentType *string `location:"header" locationName:"Content-Type" type:"string"`

	// Specifies whether the object retrieved was (true) or was not (false) a Delete
	// Marker. If false, this response header does not appear in the response.
	DeleteMarker *bool `location:"header" locationName:"x-amz-delete-marker" type:"boolean"`

	// An ETag is an opaque identifier assigned by a web server to a specific version
	// of a resource found at a URL
	ETag *string `location:"header" locationName:"ETag" type:"string"`

	// If the object expiration is configured (see PUT Bucket lifecycle), the response
	// includes this header. It includes the expiry-date and rule-id key value pairs
	// providing object expiration information. The value of the rule-id is URL
	// encoded.
	Expiration *string `location:"header" locationName:"x-amz-expiration" type:"string"`

	// The date and time at which the object is no longer cacheable.
	Expires *string `location:"header" locationName:"Expires" type:"string"`

	// Last modified date of the object
	LastModified *time.Time `location:"header" locationName:"Last-Modified" type:"timestamp"`

	// A map of metadata to store with the object in S3.
	Metadata map[string]*string `location:"headers" locationName:"x-amz-meta-" type:"map"`

	// This is set to the number of metadata entries not returned in x-amz-meta
	// headers. This can happen if you create metadata using an API like SOAP that
	// supports more flexible metadata than the REST API. For example, using SOAP,
	// you can create metadata whose values are not legal HTTP headers.
	MissingMeta *int64 `location:"header" locationName:"x-amz-missing-meta" type:"integer"`

	// The Legal Hold status for the specified object.
	ObjectLockLegalHoldStatus *string `location:"header" locationName:"x-amz-object-lock-legal-hold" type:"string" enum:"ObjectLockLegalHoldStatus"`

	// The Object Lock mode currently in place for this object.
	ObjectLockMode *string `location:"header" locationName:"x-amz-object-lock-mode" type:"string" enum:"ObjectLockMode"`

	// The date and time when this object's Object Lock will expire.
	ObjectLockRetainUntilDate *time.Time `location:"header" locationName:"x-amz-object-lock-retain-until-date" type:"timestamp" timestampFormat:"iso8601"`

	// The count of parts this object has.
	PartsCount *int64 `location:"header" locationName:"x-amz-mp-parts-count" type:"integer"`

	ReplicationStatus *string `location:"header" locationName:"x-amz-replication-status" type:"string" enum:"ReplicationStatus"`

	// If present, indicates that the requester was successfully charged for the
	// request.
	RequestCharged *string `location:"header" locationName:"x-amz-request-charged" type:"string" enum:"RequestCharged"`

	// Provides information about object restoration operation and expiration time
	// of the restored object copy.
	Restore *string `location:"header" locationName:"x-amz-restore" type:"string"`

	// If server-side encryption with a customer-provided encryption key was requested,
	// the response will include this header confirming the encryption algorithm
	// used.
	SSECustomerAlgorithm *string `location:"header" locationName:"x-amz-server-side-encryption-customer-algorithm" type:"string"`

	// If server-side encryption with a customer-provided encryption key was requested,
	// the response will include this header to provide round trip message integrity
	// verification of the customer-provided encryption key.
	SSECustomerKeyMD5 *string `location:"header" locationName:"x-amz-server-side-encryption-customer-key-MD5" type:"string"`

	// If present, specifies the ID of the AWS Key Management Service (KMS) master
	// encryption key that was used for the object.
	SSEKMSKeyId *string `location:"header" locationName:"x-amz-server-side-encryption-aws-kms-key-id" type:"string" sensitive:"true"`

	// The Server-side encryption algorithm used when storing this object in S3
	// (e.g., AES256, aws:kms).
	ServerSideEncryption *string `location:"header" locationName:"x-amz-server-side-encryption" type:"string" enum:"ServerSideEncryption"`

	StorageClass *string `location:"header" locationName:"x-amz-storage-class" type:"string" enum:"StorageClass"`

	// Version of the object.
	VersionId *string `location:"header" locationName:"x-amz-version-id" type:"string"`

	// If the bucket is configured as a website, redirects requests for this object
	// to another object in the same bucket or to an external URL. Amazon S3 stores
	// the value of this header in the object metadata.
	WebsiteRedirectLocation *string `location:"header" locationName:"x-amz-website-redirect-location" type:"string"`
}

// get object info
func (api *API) HeaderObject(bucketName string, input *HeadObjectParam) (*ObjectInfoResult, error) {
	var ret ObjectInfoResult
	err := api.PostJson(fmt.Sprintf("/api/v1/buckets/%s/object/info", bucketName), input, &ret)
	return &ret, err
}

// get object url
//@bucketName
//@objectName
//@versionId object version
//@expire Validity minutes
func (api *API) GetObjectUrl(bucketName, objectName, version string, expire int) (*ObjectUrl, error) {
	var ret ObjectUrl
	err := api.GetJson(fmt.Sprintf("/api/v1/buckets/%s/object/url?objectName=%s&version=%s&expire=%d", bucketName, objectName, version, expire), &ret)
	return &ret, err
}

type ObjectUrl struct {
	//Object url
	Url string
}

func (api *API) DeleteUser(userId string) (*Message, error) {
	var ret Message
	err := api.DeleteJson(fmt.Sprintf("/api/v1/admin/users/%s", userId), nil, &ret)
	return &ret, err
}

type PutBucketVersionParam struct {
	// The versioning state of the bucket  Valid Values: Suspended | Enabled.
	Status *string `type:"string" enum:"BucketVersioningStatus" required:"true"`

	// The concatenation of the authentication device's serial number, a space,
	// and the value that is displayed on your authentication device.
	MFA *string `location:"header" locationName:"x-amz-mfa" type:"string" required:"false"`
	//Specifies whether MFA Delete is enabled in the bucket versioning configuration. When enabled, the bucket owner
	// must include the x-amz-mfa request header in requests to change the versioning state of a bucket and to
	// permanently delete a versioned object.
	//Valid Values: Disabled | Enabled
	MFADelete *string `locationName:"MfaDelete" type:"string" enum:"MFADelete" required:"false"`
}

//PutBucketVersion
func (api *API) PutBucketVersion(bucketName string, input *PutBucketVersionParam) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/buckets/%s/version", bucketName), input, &ret)
	return &ret, err
}

//PutBucketLifecycleConfigurationParam
type PutBucketLifecycleConfigurationParam struct {
	Rules []*LifecycleRule `locationName:"Rule" type:"list" flattened:"true"`
}

type LifecycleRule struct {
	_ struct{} `type:"structure"`

	// Specifies the days since the initiation of an Incomplete Multipart Upload
	// that Lifecycle will wait before permanently removing all parts of the upload.
	AbortIncompleteMultipartUpload *AbortIncompleteMultipartUpload `type:"structure"`

	Expiration *LifecycleExpiration `type:"structure"`

	// The Filter is used to identify objects that a Lifecycle Rule applies to.
	// A Filter must have exactly one of Prefix, Tag, or And specified.
	Filter *LifecycleRuleFilter `type:"structure"`

	// Unique identifier for the rule. The value cannot be longer than 255 characters.
	ID *string `type:"string"`

	// Specifies when noncurrent object versions expire. Upon expiration, Amazon
	// S3 permanently deletes the noncurrent object versions. You set this lifecycle
	// configuration action on a bucket that has versioning enabled (or suspended)
	// to request that Amazon S3 delete noncurrent object versions at a specific
	// period in the object's lifetime.
	NoncurrentVersionExpiration *NoncurrentVersionExpiration `type:"structure"`

	NoncurrentVersionTransitions []*NoncurrentVersionTransition `locationName:"NoncurrentVersionTransition" type:"list" flattened:"true"`

	// Prefix identifying one or more objects to which the rule applies. This is
	// deprecated; use Filter instead.
	//
	// Deprecated: Prefix has been deprecated
	Prefix *string `deprecated:"true" type:"string"`

	// If 'Enabled', the rule is currently being applied. If 'Disabled', the rule
	// is not currently being applied.
	//
	// Status is a required field
	Status *string `type:"string" required:"true" enum:"ExpirationStatus"`

	Transitions []*Transition `locationName:"Transition" type:"list" flattened:"true"`
}

type AbortIncompleteMultipartUpload struct {
	_ struct{} `type:"structure"`

	// Indicates the number of days that must pass since initiation for Lifecycle
	// to abort an Incomplete Multipart Upload.
	DaysAfterInitiation *int64 `type:"integer"`
}

type LifecycleExpiration struct {
	_ struct{} `type:"structure"`

	// Indicates at what date the object is to be moved or deleted. Should be in
	// GMT ISO 8601 Format.
	Date *time.Time `type:"timestamp" timestampFormat:"iso8601"`

	// Indicates the lifetime, in days, of the objects that are subject to the rule.
	// The value must be a non-zero positive integer.
	Days *int64 `type:"integer"`

	// Indicates whether Amazon S3 will remove a delete marker with no noncurrent
	// versions. If set to true, the delete marker will be expired; if set to false
	// the policy takes no action. This cannot be specified with Days or Date in
	// a Lifecycle Expiration Policy.
	ExpiredObjectDeleteMarker *bool `type:"boolean"`
}

// Specifies when noncurrent object versions expire. Upon expiration, Amazon
// S3 permanently deletes the noncurrent object versions. You set this lifecycle
// configuration action on a bucket that has versioning enabled (or suspended)
// to request that Amazon S3 delete noncurrent object versions at a specific
// period in the object's lifetime.
type NoncurrentVersionExpiration struct {
	_ struct{} `type:"structure"`

	// Specifies the number of days an object is noncurrent before Amazon S3 can
	// perform the associated action. For information about the noncurrent days
	// calculations, see How Amazon S3 Calculates When an Object Became Noncurrent
	// (http://docs.aws.amazon.com/AmazonS3/latest/dev/s3-access-control.html) in
	// the Amazon Simple Storage Service Developer Guide.
	NoncurrentDays *int64 `type:"integer"`
}

// Container for the transition rule that describes when noncurrent objects
// transition to the STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING or GLACIER
// storage class. If your bucket is versioning-enabled (or versioning is suspended),
// you can set this action to request that Amazon S3 transition noncurrent object
// versions to the STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING or GLACIER storage
// class at a specific period in the object's lifetime.
type NoncurrentVersionTransition struct {
	_ struct{} `type:"structure"`

	// Specifies the number of days an object is noncurrent before Amazon S3 can
	// perform the associated action. For information about the noncurrent days
	// calculations, see How Amazon S3 Calculates When an Object Became Noncurrent
	// (http://docs.aws.amazon.com/AmazonS3/latest/dev/s3-access-control.html) in
	// the Amazon Simple Storage Service Developer Guide.
	NoncurrentDays *int64 `type:"integer"`

	// The class of storage used to store the object.
	StorageClass *string `type:"string" enum:"TransitionStorageClass"`
}

type Transition struct {
	_ struct{} `type:"structure"`

	// Indicates at what date the object is to be moved or deleted. Should be in
	// GMT ISO 8601 Format.
	Date *time.Time `type:"timestamp" timestampFormat:"iso8601"`

	// Indicates the lifetime, in days, of the objects that are subject to the rule.
	// The value must be a non-zero positive integer.
	Days *int64 `type:"integer"`

	// The class of storage used to store the object.
	StorageClass *string `type:"string" enum:"TransitionStorageClass"`
}

// The Filter is used to identify objects that a Lifecycle Rule applies to.
// A Filter must have exactly one of Prefix, Tag, or And specified.
type LifecycleRuleFilter struct {
	_ struct{} `type:"structure"`

	// This is used in a Lifecycle Rule Filter to apply a logical AND to two or
	// more predicates. The Lifecycle Rule will apply to any object matching all
	// of the predicates configured inside the And operator.
	And *LifecycleRuleAndOperator `type:"structure"`

	// Prefix identifying one or more objects to which the rule applies.
	Prefix *string `type:"string"`

	// This tag must exist in the object's tag set in order for the rule to apply.
	Tag *Tag `type:"structure"`
}

// This is used in a Lifecycle Rule Filter to apply a logical AND to two or
// more predicates. The Lifecycle Rule will apply to any object matching all
// of the predicates configured inside the And operator.
type LifecycleRuleAndOperator struct {
	_ struct{} `type:"structure"`

	Prefix *string `type:"string"`

	// All of these tags must exist in the object's tag set in order for the rule
	// to apply.
	Tags []*Tag `locationName:"Tag" locationNameList:"Tag" type:"list" flattened:"true"`
}

type Tag struct {
	_ struct{} `type:"structure"`

	// Name of the tag.
	//
	// Key is a required field
	Key *string `min:"1" type:"string" required:"true"`

	// Value of the tag.
	//
	// Value is a required field
	Value *string `type:"string" required:"true"`
}

//PutBucketVersion

//for example
//
//{
//
//"rules": [{
//
//"Expiration": {
//"Days":1
//},
//"ID": "delete objects and parts after one day",
//
//"Prefix": "gin",
//"Status": "Enabled",
//"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}
//
//},{
//
//"Expiration": {
//"Days":1
//},
//"ID": "delete Hank and parts after one day",
//
//"Prefix": "Hank/",
//"Status": "Enabled",
//"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}
//
//}]
//
//}
func (api *API) PutBucketLifecycleConfiguration(bucketName string, input *PutBucketLifecycleConfigurationParam) (*Message, error) {
	var ret Message
	err := api.PutJson(fmt.Sprintf("/api/v1/buckets/%s/lifecycle", bucketName), input, &ret)
	return &ret, err
}

type ObjectDeleteParam struct {
	//ObjectName
	ObjectName string `json:"objectName"`
}

//@bucketName required true
//@ObjectName required true
func (api *API) DeleteObject(bucketName string, input *ObjectDeleteParam) (*Message, error) {
	var ret Message
	err := api.DeleteJson(fmt.Sprintf("/api/v1/buckets/%s/object", bucketName), input, &ret)
	return &ret, err
}

//@bucketName required true
func (api *API) DeleteBucket(bucketName string) (*Message, error) {
	var ret Message
	err := api.DeleteJson(fmt.Sprintf("/api/v1/buckets/%s", bucketName), nil, &ret)
	return &ret, err
}

//@userId required true
//@keyId required true
func (api *API) DeleteUserKeyForUser(userId, keyId string) (*Message, error) {
	var ret Message
	err := api.DeleteJson(fmt.Sprintf("/api/v1/admin/users/%s/keys/%s", userId, keyId), nil, &ret)
	return &ret, err
}
