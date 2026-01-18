#!/usr/bin/env python3
"""
Security utilities for mobile AI agent
Handles API key management, rate limiting, and access control
"""

import os
import json
import time
import hashlib
import hmac
from functools import wraps
from pathlib import Path


class RateLimiter:
    """Rate limiter to prevent API overspending"""

    def __init__(self, max_calls_per_hour=100, max_cost_per_day=5.0):
        """
        Initialize rate limiter

        Args:
            max_calls_per_hour: Maximum API calls per hour
            max_cost_per_day: Maximum spend per day in USD
        """
        self.max_calls_per_hour = max_calls_per_hour
        self.max_cost_per_day = max_cost_per_day

        self.calls = []
        self.daily_cost = 0.0
        self.last_reset = time.time()

    def check_limit(self, estimated_cost=0.01):
        """
        Check if we can make another API call

        Args:
            estimated_cost: Estimated cost of this call in USD

        Returns:
            bool: True if call is allowed, False otherwise
        """
        now = time.time()

        # Reset daily counter if 24 hours passed
        if now - self.last_reset > 86400:  # 24 hours
            self.daily_cost = 0.0
            self.last_reset = now

        # Remove calls older than 1 hour
        hour_ago = now - 3600
        self.calls = [t for t in self.calls if t > hour_ago]

        # Check hourly limit
        if len(self.calls) >= self.max_calls_per_hour:
            return False

        # Check daily cost limit
        if self.daily_cost + estimated_cost > self.max_cost_per_day:
            return False

        # All checks passed
        self.calls.append(now)
        self.daily_cost += estimated_cost
        return True

    def get_stats(self):
        """Get current usage stats"""
        now = time.time()
        hour_ago = now - 3600
        recent_calls = [t for t in self.calls if t > hour_ago]

        return {
            "calls_last_hour": len(recent_calls),
            "max_calls_per_hour": self.max_calls_per_hour,
            "daily_cost": round(self.daily_cost, 4),
            "max_cost_per_day": self.max_cost_per_day,
            "time_until_reset": int(86400 - (now - self.last_reset))
        }


class SecureConfig:
    """Secure configuration management with environment variable support"""

    @staticmethod
    def load_config(config_path="config/config.json"):
        """
        Load configuration with environment variable override

        Environment variables take precedence over config file:
        - MISTRAL_API_KEY
        - TELEGRAM_BOT_TOKEN
        - TELEGRAM_CHAT_ID
        - SHODAN_API_KEY
        - etc.

        Args:
            config_path: Path to config file

        Returns:
            dict: Configuration with env vars applied
        """
        # Load base config
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
        else:
            config = {}

        # Override with environment variables
        env_mappings = {
            "MISTRAL_API_KEY": ("ai", "api_key"),
            "TELEGRAM_BOT_TOKEN": ("notification", "telegram_bot_token"),
            "TELEGRAM_CHAT_ID": ("notification", "telegram_chat_id"),
            "SHODAN_API_KEY": ("api_keys", "shodan"),
            "SECURITYTRAILS_API_KEY": ("api_keys", "securitytrails"),
            "VIRUSTOTAL_API_KEY": ("api_keys", "virustotal"),
            "GITHUB_TOKEN": ("github", "token"),
            "SMTP_PASSWORD": ("notification", "smtp_password"),
        }

        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                if section not in config:
                    config[section] = {}
                config[section][key] = value

        return config

    @staticmethod
    def mask_sensitive_data(config):
        """
        Mask sensitive data in config for logging

        Args:
            config: Configuration dict

        Returns:
            dict: Config with masked sensitive values
        """
        import copy
        masked = copy.deepcopy(config)

        sensitive_keys = [
            "api_key", "token", "password", "secret",
            "bot_token", "chat_id"
        ]

        def mask_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if any(sk in key.lower() for sk in sensitive_keys):
                        if value and len(str(value)) > 4:
                            obj[key] = str(value)[:4] + "***"
                    else:
                        mask_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    mask_recursive(item)

        mask_recursive(masked)
        return masked


class WebhookSecurity:
    """Security for webhook endpoints and API access"""

    def __init__(self, secret_key=None):
        """
        Initialize webhook security

        Args:
            secret_key: Secret key for HMAC signing (auto-generated if None)
        """
        if secret_key is None:
            secret_key = os.getenv("WEBHOOK_SECRET") or self._generate_secret()
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key

    @staticmethod
    def _generate_secret():
        """Generate a random secret key"""
        return hashlib.sha256(os.urandom(32)).hexdigest()

    def sign_payload(self, payload):
        """
        Sign a payload with HMAC

        Args:
            payload: Data to sign (string or bytes)

        Returns:
            str: HMAC signature
        """
        if isinstance(payload, str):
            payload = payload.encode()

        return hmac.new(
            self.secret_key,
            payload,
            hashlib.sha256
        ).hexdigest()

    def verify_signature(self, payload, signature):
        """
        Verify HMAC signature

        Args:
            payload: Data that was signed
            signature: Signature to verify

        Returns:
            bool: True if valid, False otherwise
        """
        expected = self.sign_payload(payload)
        return hmac.compare_digest(expected, signature)

    def require_signature(self, f):
        """
        Decorator to require valid signature on Flask routes

        Usage:
            @app.route('/webhook')
            @webhook_security.require_signature
            def webhook():
                return "OK"
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify

            signature = request.headers.get('X-Signature')
            if not signature:
                return jsonify({"error": "Missing signature"}), 401

            payload = request.get_data()
            if not self.verify_signature(payload, signature):
                return jsonify({"error": "Invalid signature"}), 403

            return f(*args, **kwargs)

        return decorated_function


class IPWhitelist:
    """IP whitelist for API access control"""

    def __init__(self, allowed_ips=None):
        """
        Initialize IP whitelist

        Args:
            allowed_ips: List of allowed IP addresses/ranges
        """
        self.allowed_ips = allowed_ips or ["127.0.0.1", "::1"]

    def is_allowed(self, ip):
        """
        Check if IP is allowed

        Args:
            ip: IP address to check

        Returns:
            bool: True if allowed
        """
        # Simple exact match (can be extended with CIDR support)
        return ip in self.allowed_ips

    def require_whitelist(self, f):
        """
        Decorator to require whitelisted IP on Flask routes

        Usage:
            @app.route('/admin')
            @ip_whitelist.require_whitelist
            def admin():
                return "Admin panel"
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify

            client_ip = request.remote_addr
            if not self.is_allowed(client_ip):
                return jsonify({"error": "Access denied"}), 403

            return f(*args, **kwargs)

        return decorated_function


# Example usage
if __name__ == "__main__":
    # Test rate limiter
    print("Testing Rate Limiter...")
    limiter = RateLimiter(max_calls_per_hour=10, max_cost_per_day=1.0)

    for i in range(15):
        allowed = limiter.check_limit(estimated_cost=0.01)
        print(f"Call {i+1}: {'✅ Allowed' if allowed else '❌ Blocked'}")

    print("\nRate Limiter Stats:")
    print(json.dumps(limiter.get_stats(), indent=2))

    # Test secure config
    print("\n\nTesting Secure Config...")
    config = SecureConfig.load_config("config/config.json")
    masked = SecureConfig.mask_sensitive_data(config)
    print("Masked config:")
    print(json.dumps(masked, indent=2))

    # Test webhook security
    print("\n\nTesting Webhook Security...")
    webhook = WebhookSecurity()
    payload = "test payload"
    signature = webhook.sign_payload(payload)
    print(f"Signature: {signature}")
    print(f"Valid: {webhook.verify_signature(payload, signature)}")
    print(f"Invalid: {webhook.verify_signature(payload, 'wrong_sig')}")
