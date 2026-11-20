package webui

import (
	"net/http"
	"net/url"
	"slices"
)

func (h *Handler) proxyEntranceAgentOptions(selected string) []agentOptionView {
	return slices.DeleteFunc(h.proxyAgentOptions(selected), func(option agentOptionView) bool { return option.ReverseOnly })
}

func (h *Handler) updateServerConnectivity(response http.ResponseWriter, request *http.Request) {
	if h.proxyNodes == nil {
		http.NotFound(response, request)
		return
	}
	_, form, ok := h.authorizeProxyMutation(response, request, "reverse_only")
	if !ok {
		return
	}
	id := request.PathValue("agent_id")
	if !h.registry.HasRecord(id) {
		http.NotFound(response, request)
		return
	}
	enabled, err := parseBinaryChoice(form.Get("reverse_only"), "connectivity mode")
	if err != nil {
		writeUserError(response, err.Error(), http.StatusBadRequest)
		return
	}
	h.agentMutationMu.Lock()
	defer h.agentMutationMu.Unlock()
	if !h.applyProxyTopologyMutation(response, func() error { return h.proxyNodes.SetAgentReverseOnly(id, enabled) }) {
		return
	}
	http.Redirect(response, request, "/servers/"+url.PathEscape(id)+"/manage", http.StatusSeeOther)
}
