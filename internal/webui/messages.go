package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type localizedMessage struct {
	English string `json:"en"`
	Chinese string `json:"zh-CN"`
}

// Templates and browser interactions use exactly the same message catalog.
// Keys are explicit; neither HTML nor user-entered text is rewritten at runtime.
var messages = func() map[string]localizedMessage {
	content, err := webFiles.ReadFile("messages.json")
	if err != nil {
		panic(err)
	}
	var result map[string]localizedMessage
	if err := json.Unmarshal(content, &result); err != nil {
		panic(err)
	}
	for key, value := range result {
		if key == "" || value.English == "" || value.Chinese == "" {
			panic(fmt.Sprintf("incomplete UI message %q", key))
		}
	}
	return result
}()

func messageText(locale, key string) string {
	if message, ok := messages[key]; ok {
		if normalizeLocale(locale) == localeSimplifiedChinese {
			return message.Chinese
		}
		return message.English
	}
	return key
}

// A retained form needs the new session's CSRF token after sign-in in another
// tab. This authenticated, same-origin, no-store read never submits the draft.
func (h *Handler) sessionCSRF(response http.ResponseWriter, request *http.Request) {
	session, ok := h.requireAuthentication(response, request)
	if !ok {
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(map[string]string{"csrf_token": session.CSRFToken})
}

func (h *Handler) messageScript() http.HandlerFunc {
	catalog, err := json.Marshal(messages)
	if err != nil {
		panic(err)
	}
	script, err := webFiles.ReadFile("assets/i18n.js")
	if err != nil {
		panic(err)
	}
	content := append([]byte("window.theatropolisMessages = "), catalog...)
	content = append(content, ';', '\n')
	content = append(content, script...)
	return func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		response.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = response.Write(content)
	}
}

func writeUserError(response http.ResponseWriter, detail string, status int) {
	locale := response.Header().Get("Content-Language")
	response.Header().Set("Cache-Control", "no-store")
	key := strings.TrimSpace(detail)
	if strings.HasPrefix(key, "request origin is not allowed (") {
		reason := strings.TrimPrefix(key, "request origin is not allowed ")
		http.Error(response, messageText(locale, "This request did not come from the configured Master page. Open the configured public URL and try again.")+" "+reason, status)
		return
	}
	if strings.HasPrefix(key, "could not establish a durable traffic-reset boundary: ") {
		detail := strings.TrimPrefix(key, "could not establish a durable traffic-reset boundary: ")
		http.Error(response, messageText(locale, "Traffic reset could not be safely recorded. No reset was applied. Check the Agent connection and Master accounting logs before retrying.")+"\n"+detail, status)
		return
	}
	// Unwrap known validation sentinels without parsing or rewriting user names.
	for _, prefix := range []string{"proxy node resource conflicts with existing state: ", "invalid proxy node state: "} {
		key = strings.TrimPrefix(key, prefix)
	}
	message := messageText(locale, key)
	if _, exists := messages[key]; !exists {
		help := "Check the highlighted fields and try again. If the problem continues, check the Master logs for this request."
		if status >= 500 {
			help = "Check that the Master is running and its state directory is writable, then try again. If the problem continues, check the Master logs."
		}
		message += "\n" + messageText(locale, help)
	}
	http.Error(response, message, status)
}
