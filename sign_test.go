package xk6_rsa

import "testing"

func TestRSA_Build(t *testing.T) {
	var input = make(map[string]interface{})
	input["app_key"] = "203963704"
	input["key_version"] = "v1"
	input["timestamp"] = 1644912332
	input["bool"] = true
	var input2 = make(map[string]interface{})
	input2["map2"] = "testing"
	input2["map23"] = "testing"
	input["map"] = input2
	rs := &RSA{}
	t.Log(rs.Build(input))
}
