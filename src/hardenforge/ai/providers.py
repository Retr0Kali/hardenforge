"""Isolated provider adapters (REST). Endpoints/models come from configuration, not code.

Adapters only build requests and parse responses. They never see the secret store.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Documented public API base URLs; overridable via HARDENFORGE_<PROVIDER>_ENDPOINT.
DEFAULT_ENDPOINTS = {
    "gemini": "https://generativelanguage.googleapis.com",
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}
ANTHROPIC_API_VERSION = "2023-06-01"  # API version header, not a model name


@dataclass
class ProviderConfig:
    name: str
    endpoint: str
    model: str
    price_in_per_mtok: float | None = None
    price_out_per_mtok: float | None = None


class Adapter:
    name = ""

    def build(self, cfg: ProviderConfig, key: str, system: str, prompt: str, max_tokens: int) -> tuple[str, dict, dict]:
        raise NotImplementedError

    def parse(self, body: dict[str, Any]) -> tuple[str, int, int]:
        raise NotImplementedError


class GeminiAdapter(Adapter):
    name = "gemini"

    def build(self, cfg, key, system, prompt, max_tokens):
        url = f"{cfg.endpoint}/v1beta/models/{cfg.model}:generateContent"
        headers = {"x-goog-api-key": key, "content-type": "application/json"}  # header, not URL, so keys stay out of logs
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens},
        }
        return url, headers, body

    def parse(self, body):
        try:
            text = "".join(p.get("text", "") for p in body["candidates"][0]["content"]["parts"])
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError("unexpected Gemini response shape") from e
        u = body.get("usageMetadata", {})
        return text, int(u.get("promptTokenCount", 0)), int(u.get("candidatesTokenCount", 0))


class OpenAIAdapter(Adapter):
    name = "openai"

    def build(self, cfg, key, system, prompt, max_tokens):
        url = f"{cfg.endpoint}/v1/chat/completions"
        headers = {"authorization": f"Bearer {key}", "content-type": "application/json"}
        body = {
            "model": cfg.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "max_completion_tokens": max_tokens,
        }
        return url, headers, body

    def parse(self, body):
        try:
            text = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError("unexpected OpenAI response shape") from e
        u = body.get("usage", {})
        return text, int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))


class AnthropicAdapter(Adapter):
    name = "anthropic"

    def build(self, cfg, key, system, prompt, max_tokens):
        url = f"{cfg.endpoint}/v1/messages"
        headers = {"x-api-key": key, "anthropic-version": ANTHROPIC_API_VERSION, "content-type": "application/json"}
        body = {
            "model": cfg.model, "max_tokens": max_tokens, "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        return url, headers, body

    def parse(self, body):
        try:
            text = "".join(b.get("text", "") for b in body["content"] if b.get("type") == "text")
        except (KeyError, TypeError) as e:
            raise ValueError("unexpected Anthropic response shape") from e
        u = body.get("usage", {})
        return text, int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))


ADAPTERS: dict[str, Adapter] = {a.name: a for a in (GeminiAdapter(), OpenAIAdapter(), AnthropicAdapter())}
