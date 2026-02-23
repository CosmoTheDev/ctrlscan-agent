package gateway

import (
	"embed"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed ui/*
var gatewayUI embed.FS

func (gw *Gateway) handleUIIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui" && r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}
	data, err := gatewayUI.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "UI not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (gw *Gateway) handleUIAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/ui/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := gatewayUI.ReadFile("ui/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch filepath.Ext(name) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}
