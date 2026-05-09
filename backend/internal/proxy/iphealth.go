package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ant-chrome/backend/internal/config"
)

const defaultIPPureInfoURL = "https://my.ippure.com/v1/info"

// ipQueryEndpoint 备用 IP 查询接口
type ipQueryEndpoint struct {
	url    string
	parser func(body []byte) (map[string]interface{}, error)
}

// fallbackEndpoints 当 IPPure 被 Cloudflare 拦截时的备用接口列表
// 这些接口均不使用 Cloudflare，可直接通过代理访问
var fallbackEndpoints = []ipQueryEndpoint{
	{
		// ipinfo.io：无 Cloudflare，返回标准 JSON
		url: "https://ipinfo.io/json",
		parser: func(body []byte) (map[string]interface{}, error) {
			var raw map[string]interface{}
			if err := json.Unmarshal(body, &raw); err != nil {
				return nil, err
			}
			// org 格式: "AS12345 Some ISP"
			org, _ := raw["org"].(string)
			return map[string]interface{}{
				"ip":             raw["ip"],
				"country":        raw["country"],
				"region":         raw["region"],
				"city":           raw["city"],
				"asOrganization": org,
				"fraudScore":     0,
				"isResidential":  false,
				"isBroadcast":    false,
				"_source":        "ipinfo.io",
			}, nil
		},
	},
	{
		// ip-api.com：无 Cloudflare，HTTP 接口（注意：HTTPS 需付费，用 HTTP）
		url: "http://ip-api.com/json/?fields=status,message,country,regionName,city,org,query",
		parser: func(body []byte) (map[string]interface{}, error) {
			var raw map[string]interface{}
			if err := json.Unmarshal(body, &raw); err != nil {
				return nil, err
			}
			if status, _ := raw["status"].(string); status != "success" {
				msg, _ := raw["message"].(string)
				return nil, fmt.Errorf("ip-api.com 返回失败: %s", msg)
			}
			return map[string]interface{}{
				"ip":             raw["query"],
				"country":        raw["country"],
				"region":         raw["regionName"],
				"city":           raw["city"],
				"asOrganization": raw["org"],
				"fraudScore":     0,
				"isResidential":  false,
				"isBroadcast":    false,
				"_source":        "ip-api.com",
			}, nil
		},
	},
	{
		// ifconfig.me：极简接口，只返回 IP 文本
		url: "https://ifconfig.me/ip",
		parser: func(body []byte) (map[string]interface{}, error) {
			ip := strings.TrimSpace(string(body))
			if ip == "" {
				return nil, fmt.Errorf("ifconfig.me 返回空")
			}
			return map[string]interface{}{
				"ip":             ip,
				"country":        "",
				"region":         "",
				"city":           "",
				"asOrganization": "",
				"fraudScore":     0,
				"isResidential":  false,
				"isBroadcast":    false,
				"_source":        "ifconfig.me",
			}, nil
		},
	},
}

// FetchIPPureInfo 通过指定代理链路查询出口 IP 健康信息。
// 优先使用 IPPure 接口，若被 Cloudflare 拦截（403）则自动降级到备用接口。
func FetchIPPureInfo(
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
) (map[string]interface{}, error) {
	src := ""
	for _, item := range proxies {
		if strings.EqualFold(item.ProxyId, proxyId) {
			src = strings.TrimSpace(item.ProxyConfig)
			break
		}
	}
	if src == "" {
		return nil, fmt.Errorf("未找到代理配置")
	}

	client, err := buildIPPureHTTPClient(src, proxyId, proxies, xrayMgr, singboxMgr, 20*time.Second)
	if err != nil {
		return nil, err
	}

	// 先尝试 IPPure 主接口
	data, primaryErr := fetchIPPure(client)
	if primaryErr == nil {
		return data, nil
	}

	// 若是 Cloudflare 拦截（403）则尝试备用接口
	if isCloudflareBlock(primaryErr) {
		var lastErr error
		for _, ep := range fallbackEndpoints {
			data, err := fetchFromEndpoint(client, ep)
			if err == nil {
				return data, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, fmt.Errorf("IPPure 被 Cloudflare 拦截，备用接口也失败: %w", lastErr)
		}
	}

	return nil, primaryErr
}

func fetchIPPure(client *http.Client) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, defaultIPPureInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://my.ippure.com/")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 IPPure 接口失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 IPPure 响应失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("IPPure HTTP %d: %s", resp.StatusCode, bodySnippet(body, 180))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("IPPure JSON 解析失败: %w", err)
	}
	return result, nil
}

func fetchFromEndpoint(client *http.Client, ep ipQueryEndpoint) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, ep.url, nil)
	if err != nil {
		return nil, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "curl/8.4.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s 失败: %w", ep.url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 响应失败: %w", ep.url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s HTTP %d: %s", ep.url, resp.StatusCode, bodySnippet(body, 120))
	}

	return ep.parser(body)
}

// isCloudflareBlock 判断错误是否为 Cloudflare 拦截（403 + Challenge 页面）
func isCloudflareBlock(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "IPPure HTTP 403") &&
		(strings.Contains(msg, "Just a moment") ||
			strings.Contains(msg, "Cloudflare") ||
			strings.Contains(msg, "DOCTYPE html"))
}

func buildIPPureHTTPClient(
	src string,
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
	timeout time.Duration,
) (*http.Client, error) {
	return buildProxyHTTPClient(src, proxyId, proxies, xrayMgr, singboxMgr, timeout)
}

func bodySnippet(body []byte, max int) string {
	s := strings.TrimSpace(string(body))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
