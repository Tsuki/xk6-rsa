package xk6_rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"go.k6.io/k6/js/modules"
	"golang.org/x/xerrors"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func init() {
	modules.Register("k6/x/rsa", new(RSA))
}

// RSA is the k6 say extension.
type RSA struct{}

// Sign is a wrapper for Go crypto/rsa
func (*RSA) Sign(input map[string]interface{}, pk string) string {
	_, ss, err := buildDataStr(input, pk)
	fmt.Println(ss)
	if err != nil {
		return "error"
	}
	return ss
}
func (*RSA) Build(input map[string]interface{}) string {
	return strings.Join(buildDataStrByTagMap(input, "", false), "&")
}

func BytesToPrivateKey(priv []byte, password string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc && password != "" {
		b, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func buildDataStr(s interface{}, pk string) (string, string, error) {
	keyS, err := BytesToPrivateKey([]byte(pk), "")
	jsonmap := buildDataStrByTagMap(s, "", false)
	sort.Strings(jsonmap)
	dataStr := strings.Join(jsonmap, "&")
	rng := rand.Reader
	message := []byte(dataStr)
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rng, keyS, crypto.SHA256, hashed[:])
	if err != nil {
		return "", "", xerrors.Errorf("Error from signing: %w", err)
	}
	signatureS := base64.StdEncoding.EncodeToString(signature)
	return dataStr, signatureS, nil
}

func buildDataStrByTagMap(s interface{}, pre string, isSub bool) []string {
	var result []string
	if s == nil {
		return []string{}
	}
	rt := reflect.TypeOf(s)
	refv := reflect.ValueOf(s)
	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
		refv = refv.Elem()
	}
	if !isSub && rt.Kind() != reflect.Struct && rt.Kind() != reflect.Interface && rt.Kind() != reflect.Map {
		return []string{}
	}

	if rt.Kind() == reflect.Map {
		for _, e := range refv.MapKeys() {
			k := e.String()
			if pre != "" {
				k = fmt.Sprintf("%s[%s]", pre, k)
			}
			v := refv.MapIndex(e).Elem()
			var vStr string
			switch v.Kind() {
			case reflect.Int, reflect.Int64:
				vStr = strconv.Itoa(int(v.Int()))
				sort.Strings(result)
				result = append(result, fmt.Sprintf("%s=%s", k, vStr))
			case reflect.String:
				vStr = url.QueryEscape(strings.TrimSpace(v.String()))
				sort.Strings(result)
				result = append(result, fmt.Sprintf("%s=%s", k, vStr))
			case reflect.Bool:
				vStr = strconv.FormatBool(v.Bool())
				sort.Strings(result)
				result = append(result, fmt.Sprintf("%s=%s", k, vStr))
			case reflect.Map:
				result = append(result, buildDataStrByTagMap(v.Interface(), k, true)...)
			case reflect.Slice:
				if v.Len() == 0 {
					result = append(result, fmt.Sprintf("%s=%%5B%%5D", k))
					continue
				}
				for i := 0; i < v.Len(); i++ {
					vSlice := buildDataStrByTagMap(v.Index(i).Interface(), e.String()+"[]", true)
					sort.Strings(vSlice)
					result = append(result, strings.Join(vSlice, "&"))
				}
			}
		}
		return result
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		k := strings.Split(f.Tag.Get("json"), ",")[0] // use split to ignore tag "options"
		if k == "-" || k == "sign" {
			continue
		}
		var vStr string
		v := refv.FieldByName(f.Name)
		kind := f.Type.Kind()
		if pre != "" {
			k = fmt.Sprintf("%s[%s]", pre, k)
		}
		switch kind {
		case reflect.Ptr:
			if v.IsNil() {
				continue
			}
			v = v.Elem()
			fallthrough
		case reflect.Struct, reflect.Interface:
			result = append(result, buildDataStrByTagMap(v.Interface(), k, true)...)
		case reflect.Slice:
			if v.Len() == 0 {
				result = append(result, fmt.Sprintf("%s=%%5B%%5D", k))
				continue
			}
			for i := 0; i < v.Len(); i++ {
				vSlice := buildDataStrByTagMap(v.Index(i).Interface(), k+"[]", true)
				sort.Strings(vSlice)
				result = append(result, strings.Join(vSlice, "&"))
			}
		case reflect.Int, reflect.Uint, reflect.String:
			if kind == reflect.Int {
				vStr = strconv.Itoa(int(v.Int()))
			} else if kind == reflect.Uint {
				vStr = strconv.Itoa(int(v.Uint()))
			} else if kind == reflect.String {
				vStr = v.String()
			}
			vStr = url.QueryEscape(strings.TrimSpace(vStr))
			sort.Strings(result)
			result = append(result, fmt.Sprintf("%s=%s", k, vStr))
		}
	}
	return result
}
