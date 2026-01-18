#!/usr/bin/env python3
"""
Devstral Vibe AI Integration Module
AI-powered intelligent decision making for bug bounty reconnaissance

Supports:
- Local inference (CPU-optimized, quantized models)
- API fallback (Mistral API, HuggingFace, Ollama)
- Intelligent scan prioritization
- Vulnerability analysis
- PoC generation
- Report enhancement
"""

import os
import json
import logging
from typing import List, Dict, Optional
from pathlib import Path

# Try importing AI libraries (gracefully handle if not installed)
try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("transformers not installed. Install with: pip install transformers")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class DevstralVibeAgent:
    """AI-powered intelligent reconnaissance agent"""

    def __init__(self, config: Dict):
        """
        Initialize Devstral Vibe agent

        Args:
            config: Configuration dictionary with AI settings
        """
        self.config = config
        self.ai_config = config.get("ai", {})
        self.mode = self.ai_config.get("mode", "api")  # local, api, or hybrid
        self.logger = logging.getLogger(__name__)

        # Model state
        self.model = None
        self.tokenizer = None
        self.api_key = self.ai_config.get("api_key")
        self.api_endpoint = self.ai_config.get("api_endpoint", "https://api.mistral.ai/v1/chat/completions")

        # Initialize based on mode
        if self.mode in ["local", "hybrid"]:
            self._load_local_model()

    def _load_local_model(self):
        """Load local AI model (CPU-optimized)"""
        if not TRANSFORMERS_AVAILABLE:
            self.logger.error("transformers library not available. Falling back to API mode.")
            self.mode = "api"
            return

        try:
            model_name = self.ai_config.get("model_name", "mistralai/Mistral-7B-Instruct-v0.2")
            self.logger.info(f"Loading model: {model_name}")

            # For CPU-friendly inference, use quantized models
            # Note: For PythonAnywhere, you might need to use smaller models or API
            self.logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)

            # Check if we should load the model (memory constraints)
            load_full_model = self.ai_config.get("load_full_model", False)

            if load_full_model:
                self.logger.info("Loading full model (this may take time and memory)...")
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    device_map="cpu",
                    load_in_8bit=False,  # 8-bit quantization requires GPU
                    low_cpu_mem_usage=True
                )
                self.logger.info("Model loaded successfully!")
            else:
                self.logger.info("Skipping model load (using API fallback)")
                self.mode = "api"

        except Exception as e:
            self.logger.error(f"Failed to load local model: {e}")
            self.logger.info("Falling back to API mode")
            self.mode = "api"

    def _generate_local(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate response using local model"""
        if not self.model or not self.tokenizer:
            raise RuntimeError("Local model not loaded")

        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=0.7,
                do_sample=True,
                top_p=0.95
            )
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

            # Extract just the generated part (remove prompt)
            response = response[len(prompt):].strip()
            return response

        except Exception as e:
            self.logger.error(f"Local generation failed: {e}")
            raise

    def _generate_api_mistral(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate response using Mistral API"""
        if not self.api_key:
            raise ValueError("Mistral API key not configured")

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            data = {
                "model": self.ai_config.get("api_model", "mistral-small-latest"),
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": 0.7
            }

            response = requests.post(
                self.api_endpoint,
                headers=headers,
                json=data,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            return result["choices"][0]["message"]["content"]

        except Exception as e:
            self.logger.error(f"Mistral API call failed: {e}")
            raise

    def _generate_api_ollama(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate response using local Ollama server"""
        ollama_url = self.ai_config.get("ollama_url", "http://localhost:11434/api/generate")

        try:
            data = {
                "model": self.ai_config.get("ollama_model", "mistral"),
                "prompt": prompt,
                "stream": False
            }

            response = requests.post(ollama_url, json=data, timeout=60)
            response.raise_for_status()

            result = response.json()
            return result.get("response", "")

        except Exception as e:
            self.logger.error(f"Ollama API call failed: {e}")
            raise

    def _generate_api_huggingface(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate response using HuggingFace Inference API"""
        hf_token = self.ai_config.get("huggingface_token")
        if not hf_token:
            raise ValueError("HuggingFace token not configured")

        model = self.ai_config.get("huggingface_model", "mistralai/Mistral-7B-Instruct-v0.2")
        api_url = f"https://api-inference.huggingface.co/models/{model}"

        try:
            headers = {"Authorization": f"Bearer {hf_token}"}
            data = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": max_tokens,
                    "temperature": 0.7,
                    "return_full_text": False
                }
            }

            response = requests.post(api_url, headers=headers, json=data, timeout=60)
            response.raise_for_status()

            result = response.json()
            if isinstance(result, list) and len(result) > 0:
                return result[0].get("generated_text", "")
            return str(result)

        except Exception as e:
            self.logger.error(f"HuggingFace API call failed: {e}")
            raise

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """
        Generate AI response using configured method

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated response string
        """
        api_provider = self.ai_config.get("api_provider", "mistral")

        try:
            if self.mode == "local" and self.model:
                return self._generate_local(prompt, max_tokens)

            elif self.mode == "api" or self.mode == "hybrid":
                if api_provider == "mistral":
                    return self._generate_api_mistral(prompt, max_tokens)
                elif api_provider == "ollama":
                    return self._generate_api_ollama(prompt, max_tokens)
                elif api_provider == "huggingface":
                    return self._generate_api_huggingface(prompt, max_tokens)
                else:
                    raise ValueError(f"Unknown API provider: {api_provider}")

            else:
                raise RuntimeError("No AI generation method available")

        except Exception as e:
            self.logger.error(f"Generation failed: {e}")
            # If hybrid mode and local failed, try API
            if self.mode == "hybrid" and api_provider:
                try:
                    self.logger.info("Falling back to API...")
                    return self._generate_api_mistral(prompt, max_tokens)
                except:
                    pass

            raise

    def prioritize_targets(self, subdomains: List[str], context: str = "") -> List[Dict]:
        """
        Use AI to prioritize which subdomains to scan first

        Args:
            subdomains: List of discovered subdomains
            context: Additional context about the target

        Returns:
            List of prioritized subdomains with reasoning
        """
        self.logger.info(f"AI prioritizing {len(subdomains)} subdomains...")

        # Limit to reasonable number for prompt
        sample = subdomains[:50]

        prompt = f"""You are a bug bounty hunter analyzing subdomains. Prioritize the following subdomains based on likelihood of vulnerabilities.

Context: {context}

Subdomains:
{chr(10).join(sample)}

Provide your top 10 priority targets in JSON format with this structure:
{{
  "priorities": [
    {{"subdomain": "example.com", "score": 9, "reason": "API endpoint, likely has authentication"}},
    ...
  ]
}}

Focus on:
- API endpoints (api., rest., graphql.)
- Admin panels (admin., console., panel.)
- Development environments (dev., staging., test.)
- Authentication services (auth., login., sso.)
- Legacy systems (old., legacy., v1.)

Respond ONLY with valid JSON, no other text."""

        try:
            response = self.generate(prompt, max_tokens=1000)

            # Try to parse JSON from response
            # Sometimes models wrap JSON in markdown code blocks
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            else:
                json_str = response

            result = json.loads(json_str.strip())
            return result.get("priorities", [])

        except Exception as e:
            self.logger.error(f"Failed to prioritize targets: {e}")
            # Fallback: simple keyword-based prioritization
            return self._fallback_prioritize(sample)

    def _fallback_prioritize(self, subdomains: List[str]) -> List[Dict]:
        """Simple keyword-based prioritization fallback"""
        high_value_keywords = [
            'api', 'admin', 'console', 'panel', 'dev', 'staging',
            'test', 'auth', 'login', 'sso', 'portal', 'internal'
        ]

        priorities = []
        for subdomain in subdomains:
            score = 0
            reasons = []

            for keyword in high_value_keywords:
                if keyword in subdomain.lower():
                    score += 2
                    reasons.append(f"Contains '{keyword}'")

            if score > 0:
                priorities.append({
                    "subdomain": subdomain,
                    "score": min(score, 10),
                    "reason": ", ".join(reasons)
                })

        return sorted(priorities, key=lambda x: x["score"], reverse=True)[:10]

    def analyze_vulnerability(self, finding: Dict) -> Dict:
        """
        Use AI to analyze a potential vulnerability

        Args:
            finding: Dictionary containing vulnerability details

        Returns:
            Enhanced finding with AI analysis
        """
        self.logger.info(f"AI analyzing finding: {finding.get('type', 'unknown')}")

        prompt = f"""You are a security researcher analyzing a potential vulnerability.

Finding Details:
- Type: {finding.get('type', 'Unknown')}
- Host: {finding.get('host', 'N/A')}
- Severity: {finding.get('severity', 'Unknown')}
- Details: {finding.get('details', 'No details')}

Analyze this finding and provide:
1. Exploitability assessment (1-10)
2. Potential impact
3. Suggested testing steps
4. CVSS score estimate
5. Whether this is worth reporting

Respond in JSON format:
{{
  "exploitability": 7,
  "impact": "Could lead to...",
  "testing_steps": ["Step 1", "Step 2"],
  "cvss_estimate": "7.5",
  "worth_reporting": true,
  "reasoning": "Explanation..."
}}

Respond ONLY with valid JSON."""

        try:
            response = self.generate(prompt, max_tokens=800)

            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            else:
                json_str = response

            analysis = json.loads(json_str.strip())

            # Enhance original finding
            finding["ai_analysis"] = analysis
            return finding

        except Exception as e:
            self.logger.error(f"Failed to analyze vulnerability: {e}")
            finding["ai_analysis"] = {"error": str(e)}
            return finding

    def generate_poc(self, vulnerability: Dict) -> str:
        """
        Generate a proof-of-concept exploit for a vulnerability

        Args:
            vulnerability: Vulnerability details

        Returns:
            PoC code/commands as string
        """
        self.logger.info(f"AI generating PoC for: {vulnerability.get('type', 'unknown')}")

        vuln_type = vulnerability.get('type', 'Unknown')
        host = vulnerability.get('host', 'target.com')
        details = vulnerability.get('details', '')

        prompt = f"""You are a security researcher creating a proof-of-concept.

Vulnerability:
- Type: {vuln_type}
- Host: {host}
- Details: {details}

Generate a safe, non-destructive proof-of-concept that demonstrates this vulnerability.
Include:
1. Command-line examples (curl, etc.)
2. Python script if applicable
3. Expected output
4. Safety notes

Format your response as:
## PoC for {vuln_type}

### Steps:
1. ...

### Commands:
```bash
curl ...
```

### Expected Result:
...

### Safety Notes:
- Do not use on production without permission
- ...
"""

        try:
            poc = self.generate(prompt, max_tokens=1500)
            return poc

        except Exception as e:
            self.logger.error(f"Failed to generate PoC: {e}")
            return f"Error generating PoC: {e}"

    def enhance_report(self, report_content: str, findings: List[Dict]) -> str:
        """
        Use AI to enhance and polish a security report

        Args:
            report_content: Raw report markdown
            findings: List of findings

        Returns:
            Enhanced report content
        """
        self.logger.info("AI enhancing report...")

        prompt = f"""You are a professional security report writer. Enhance this bug bounty report.

Current Report:
{report_content[:2000]}  # Limit for token efficiency

Improve:
1. Executive summary
2. Technical accuracy
3. Impact assessment
4. Remediation recommendations
5. Professional tone

Provide the enhanced version maintaining markdown format."""

        try:
            enhanced = self.generate(prompt, max_tokens=2000)
            return enhanced

        except Exception as e:
            self.logger.error(f"Failed to enhance report: {e}")
            return report_content  # Return original on failure

    def suggest_next_steps(self, scan_results: Dict) -> List[str]:
        """
        AI suggests what to do next based on scan results

        Args:
            scan_results: Dictionary of scan results

        Returns:
            List of suggested next steps
        """
        self.logger.info("AI suggesting next steps...")

        prompt = f"""Based on these reconnaissance results, suggest the next steps for bug hunting.

Results Summary:
- Subdomains found: {scan_results.get('subdomain_count', 0)}
- Live hosts: {scan_results.get('live_host_count', 0)}
- Findings: {scan_results.get('finding_count', 0)}

Top findings:
{json.dumps(scan_results.get('top_findings', [])[:5], indent=2)}

Provide 5-10 specific, actionable next steps as a JSON array:
["Step 1: Test the API endpoint at...", "Step 2: Check for IDOR in...", ...]

Respond ONLY with a JSON array of strings."""

        try:
            response = self.generate(prompt, max_tokens=500)

            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            else:
                json_str = response

            steps = json.loads(json_str.strip())
            return steps if isinstance(steps, list) else []

        except Exception as e:
            self.logger.error(f"Failed to suggest next steps: {e}")
            return ["Manual review of findings recommended"]


# Convenience function for standalone use
def create_ai_agent(config_path: str = "config/config.json") -> DevstralVibeAgent:
    """Create and return an AI agent from config file"""
    with open(config_path, 'r') as f:
        config = json.load(f)
    return DevstralVibeAgent(config)


if __name__ == "__main__":
    # Test the AI agent
    logging.basicConfig(level=logging.INFO)

    test_config = {
        "ai": {
            "mode": "api",
            "api_provider": "ollama",  # or "mistral", "huggingface"
            "api_key": "your-key-here",
            "ollama_url": "http://localhost:11434/api/generate",
            "ollama_model": "mistral"
        }
    }

    agent = DevstralVibeAgent(test_config)

    # Test prioritization
    test_subdomains = [
        "www.example.com",
        "api.example.com",
        "admin.example.com",
        "blog.example.com",
        "dev.example.com"
    ]

    priorities = agent.prioritize_targets(test_subdomains, "E-commerce platform")
    print("Prioritized targets:")
    print(json.dumps(priorities, indent=2))
