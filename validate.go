package main

import (
	"encoding/json"
	// "strings"

	onelog "github.com/francoispqt/onelog"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"

	"fmt"
	"regexp"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"

	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

// func validate(payload []byte) ([]byte, error) {
// 	// Create a Settings instance from the ValidationRequest object
// 	settings, err := NewSettingsFromValidationReq(&validationRequest)
// 	if err != nil {
// 		return kubewarden.RejectRequest(
// 			kubewarden.Message(err.Error()),
// 			kubewarden.Code(400))
// 	}

// 	if settings.IsNameDenied(pod.Metadata.Name) {
// 		logger.InfoWithFields("rejecting pod object", func(e onelog.Entry) {
// 			e.String("name", pod.Metadata.Name)
// 			e.String("denied_names", strings.Join(settings.DeniedNames, ","))
// 		})

// 		return kubewarden.RejectRequest(
// 			kubewarden.Message(
// 				fmt.Sprintf("The '%s' name is on the deny list", pod.Metadata.Name)),
// 			kubewarden.NoCode)
// 	}

// 	return kubewarden.AcceptRequest()
// }

func validate(payload []byte) ([]byte, error) {

	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Access the **raw** JSON that describes the object
	podJSON := validationRequest.Request.Object

	// Try to create a Pod instance using the RAW JSON we got from the
	// ValidationRequest.
	pod := &corev1.Pod{}
	if err := json.Unmarshal([]byte(podJSON), pod); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("Cannot decode Pod object: %s", err.Error())),
			kubewarden.Code(400))
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		e.String("name", pod.Metadata.Name)
		e.String("namespace", pod.Metadata.Namespace)
	})

	// extract the name of the namespace by looking into the resource metadata atrribute
	namespaceName := gjson.GetBytes(payload, "request.object.metadata.name")
	namespaceNameMatches, err := regexp.MatchString(`^t-\w+-\w+`, namespaceName.String())
	if err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Error while validating namespace name: %s", err.Error())), kubewarden.NoCode)
	}

	if !namespaceNameMatches {
		rejectionMessage := fmt.Sprintf("Namespace name %s does not match the expected pattern", namespaceName.String())
		return kubewarden.RejectRequest(kubewarden.Message(rejectionMessage), kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
