// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package v1

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonA74debfbDecodeGithubComKubewardenK8sObjectsApimachineryPkgApisMetaV1(in *jlexer.Lexer, out *Preconditions) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "resourceVersion":
			out.ResourceVersion = string(in.String())
		case "uid":
			out.UID = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonA74debfbEncodeGithubComKubewardenK8sObjectsApimachineryPkgApisMetaV1(out *jwriter.Writer, in Preconditions) {
	out.RawByte('{')
	first := true
	_ = first
	if in.ResourceVersion != "" {
		const prefix string = ",\"resourceVersion\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.ResourceVersion))
	}
	if in.UID != "" {
		const prefix string = ",\"uid\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.UID))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Preconditions) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonA74debfbEncodeGithubComKubewardenK8sObjectsApimachineryPkgApisMetaV1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Preconditions) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonA74debfbEncodeGithubComKubewardenK8sObjectsApimachineryPkgApisMetaV1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Preconditions) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonA74debfbDecodeGithubComKubewardenK8sObjectsApimachineryPkgApisMetaV1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Preconditions) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonA74debfbDecodeGithubComKubewardenK8sObjectsApimachineryPkgApisMetaV1(l, v)
}