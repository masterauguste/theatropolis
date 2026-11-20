package webui

import (
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

type spaEnvelope struct {
	View       string   `json:"view"`
	Status     int      `json:"status"`
	Locale     string   `json:"locale"`
	Error      string   `json:"error,omitempty"`
	ErrorField string   `json:"errorField,omitempty"`
	Notice     string   `json:"notice,omitempty"`
	Data       pageData `json:"data"`
}

type spaSessionInfo struct {
	Authenticated bool   `json:"authenticated"`
	Role          string `json:"role"`
	Username      string `json:"username,omitempty"`
	CSRFToken     string `json:"csrfToken,omitempty"`
	Locale        string `json:"locale"`
	PublicURL     string `json:"publicURL"`
	MasterAddress string `json:"masterAddress"`
	MasterVersion string `json:"masterVersion"`
	UnifiedLogin  bool   `json:"unifiedLogin"`
	LegacyLogin   bool   `json:"legacyLogin"`
}

func wantsJSON(request *http.Request) bool {
	if request.Header.Get("X-Theatropolis-SPA") == "1" || request.Header.Get("X-Theatropolis-Form") == "1" {
		return true
	}
	return strings.Contains(strings.ToLower(request.Header.Get("Accept")), "application/json")
}

func acceptsHTML(request *http.Request) bool {
	return strings.Contains(strings.ToLower(request.Header.Get("Accept")), "text/html")
}

func wantsSPAShell(request *http.Request) bool {
	return request.Method == http.MethodGet && !wantsJSON(request) && acceptsHTML(request)
}

func (h *Handler) spaPage(handler http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if wantsSPAShell(request) {
			if _, ok := h.requireAuthentication(response, request); !ok {
				return
			}
			h.serveSPAIndex(response)
			return
		}
		handler(response, request)
	}
}

func (h *Handler) spaPublicPage(handler http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if wantsSPAShell(request) {
			switch request.URL.Path {
			case "/login":
				if _, ok := h.authenticate(response, request); ok {
					http.Redirect(response, request, "/servers", http.StatusSeeOther)
					return
				}
				if h.endUserAccess != nil && h.endUserAccess.Unified() {
					if _, ok := h.authenticateEndUser(request); ok {
						http.Redirect(response, request, "/portal", http.StatusSeeOther)
						return
					}
				}
			case "/portal/login":
				if h.endUserAccess == nil {
					http.NotFound(response, request)
					return
				}
				if h.endUserAccess.Unified() {
					http.Redirect(response, request, "/login", http.StatusSeeOther)
					return
				}
				if _, ok := h.authenticateEndUser(request); ok {
					http.Redirect(response, request, "/portal", http.StatusSeeOther)
					return
				}
			case "/claim":
				if h.endUserAccess == nil {
					http.NotFound(response, request)
					return
				}
			}
			h.serveSPAIndex(response)
			return
		}
		handler(response, request)
	}
}

func (h *Handler) spaPortalPage(handler http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if wantsSPAShell(request) {
			if h.endUserAccess == nil {
				http.NotFound(response, request)
				return
			}
			if _, ok := h.requireEndUserAuthentication(response, request); !ok {
				return
			}
			h.serveSPAIndex(response)
			return
		}
		handler(response, request)
	}
}

func (h *Handler) serveSPAIndex(response http.ResponseWriter) {
	h.serveSPAIndexStatus(response, http.StatusOK)
}

func (h *Handler) serveSPAIndexStatus(response http.ResponseWriter, status int) {
	content, err := webFiles.ReadFile("dist/index.html")
	if err != nil {
		writeUserError(response, "frontend bundle is not built", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(content)
}

func (h *Handler) serveSPAAssets(response http.ResponseWriter, request *http.Request) {
	assetPath := strings.TrimPrefix(request.URL.Path, "/assets/")
	cleaned := path.Clean("/" + assetPath)
	if cleaned == "/" || strings.HasPrefix(cleaned, "/.") || strings.Contains(cleaned, "/.") {
		http.NotFound(response, request)
		return
	}
	fullPath := "dist/assets" + cleaned
	content, err := fs.ReadFile(webFiles, fullPath)
	if err != nil {
		http.NotFound(response, request)
		return
	}
	contentType := mime.TypeByExtension(path.Ext(cleaned))
	if contentType == "" {
		contentType = http.DetectContentType(content)
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(content)
}

func (h *Handler) apiMessages(response http.ResponseWriter, request *http.Request) {
	locale := normalizeLocale(response.Header().Get("Content-Language"))
	if requested := request.URL.Query().Get("locale"); requested == localeEnglish || requested == localeSimplifiedChinese {
		locale = requested
	}
	catalog := make(map[string]string, len(messages))
	for key, value := range messages {
		if locale == localeSimplifiedChinese {
			catalog[key] = value.Chinese
		} else {
			catalog[key] = value.English
		}
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"locale":   locale,
		"messages": catalog,
	})
}

func (h *Handler) apiSession(response http.ResponseWriter, request *http.Request) {
	locale := normalizeLocale(response.Header().Get("Content-Language"))
	info := spaSessionInfo{
		Locale:        locale,
		PublicURL:     h.publicURL,
		MasterAddress: h.masterAddress,
		MasterVersion: h.version,
		UnifiedLogin:  h.endUserAccess != nil && h.endUserAccess.Unified(),
		LegacyLogin:   h.access.Mode() == LegacyAccessKey,
	}
	if session, ok := h.authenticate(response, request); ok {
		info.Authenticated = true
		info.Role = "admin"
		info.CSRFToken = session.CSRFToken
	} else if h.endUserAccess != nil {
		if portalSession, ok := h.authenticateEndUser(request); ok {
			info.Authenticated = true
			info.Role = "user"
			info.Username = portalSession.LoginUsername
			info.CSRFToken = portalSession.CSRFToken
		}
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(response).Encode(info)
}

func writeUnauthorizedJSON(response http.ResponseWriter, redirect string) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(response).Encode(map[string]string{
		"error":    "unauthorized",
		"redirect": redirect,
	})
}

type spaRedirectResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
	intercepted bool
}

func (w *spaRedirectResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *spaRedirectResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if status == http.StatusSeeOther || status == http.StatusFound {
		if location := w.Header().Get("Location"); location != "" {
			w.intercepted = true
			w.Header().Del("Location")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.ResponseWriter.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w.ResponseWriter).Encode(map[string]any{
				"ok":       true,
				"redirect": location,
			})
			return
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *spaRedirectResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.intercepted {
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
}

func normalizeViewName(name string) string {
	return strings.TrimSuffix(name, ".html")
}
