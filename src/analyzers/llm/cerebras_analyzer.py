#!/usr/bin/env python3
"""
Cerebras GPT-OSS-120B Security Analyzer
Optimized for MCP vulnerability detection with 64K context
"""

import os
import time
from typing import Any

from cerebras.cloud.sdk import Cerebras

from .base_analyzer import AnalysisType, BaseLLMAnalyzer, LLMFinding, LLMRequest, LLMResponse
from .prompts import MCPSecurityPrompts, ThreatCategory


class CerebrasAnalyzer(BaseLLMAnalyzer):
    """Cerebras-powered security analysis with GPT-OSS-120B"""

    def __init__(self, api_key: str | None = None, debug: bool = False):
        super().__init__(max_context_tokens=64000)  # 64K context window
        self.client = Cerebras(
            api_key=api_key or os.environ.get("CEREBRAS_API_KEY")
        )
        self.model = "gpt-oss-120b"  # Cerebras GPT-OSS-120B model
        self.prompts = MCPSecurityPrompts()
        self.debug = debug or os.environ.get("LLM_DEBUG", "").lower() == "true"

    def analyze(self, request: LLMRequest) -> LLMResponse:
        """Analyze code with Cerebras using centralized prompts"""
        start_time = time.time()

        # Map analysis type to threat category
        threat_category = self._map_analysis_to_threat(request.analysis_type)

        # Build prompt using centralized system
        system_prompt = self.prompts.get_base_system_prompt()
        user_prompt = self.prompts.build_analysis_prompt(
            code=request.code_snippet,
            file_path=request.file_path,
            threat_category=threat_category,
            context=request.context
        )

        try:
            # Call Cerebras API
            completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                model=self.model,
                temperature=0.1,  # Low for consistent security analysis
                max_tokens=request.max_tokens,
                top_p=0.95
            )

            # Parse response
            response_text = completion.choices[0].message.content

            # Debug logging
            if self.debug:
                print(f"\n[DEBUG] LLM Response for {request.file_path}:")
                print(f"[DEBUG] Raw response length: {len(response_text)} chars")
                if len(response_text) < 500:
                    print(f"[DEBUG] Full response: {response_text}")
                else:
                    print(f"[DEBUG] First 250 chars: {response_text[:250]}")
                    print(f"[DEBUG] Last 250 chars: {response_text[-250:]}")

            parsed_response = self._parse_json_response(response_text)

            # Log parsing error with file context (skip test files and pkg files)
            if parsed_response is None and response_text:
                # Only log for important files (not tests, packages, or vendor)
                try:
                    from src.analyzers.shared_constants import should_skip_for_llm
                except ImportError:
                    # Fallback import
                    import sys
                    from pathlib import Path
                    sys.path.append(str(Path(__file__).parent.parent.parent))
                    from src.analyzers.shared_constants import should_skip_for_llm

                if not should_skip_for_llm(request.file_path):
                    print(f"Failed to parse JSON for {request.file_path}: Response too malformed")
                    if self.debug:
                        print(f"[DEBUG] Parsing failed. Response was: {response_text[:500]}")

            # Convert to LLMFinding objects
            findings = []
            if parsed_response and 'findings' in parsed_response:
                for finding_data in parsed_response['findings']:
                    findings.append(LLMFinding(
                        severity=finding_data.get('severity', 'MEDIUM'),
                        attack_vector=finding_data.get('attack_vector', 'unknown'),
                        description=finding_data.get('description', ''),
                        line_numbers=finding_data.get('line_numbers', []),
                        confidence=finding_data.get('confidence', 0.5),
                        exploitation_scenario=finding_data.get('exploitation_scenario', ''),
                        remediation=finding_data.get('remediation', ''),
                        evidence=finding_data.get('evidence', {})
                    ))

            # Calculate risk score
            risk_score = parsed_response.get('risk_score', 0.0) if parsed_response else 0.0
            summary = parsed_response.get('summary', 'Analysis complete') if parsed_response else 'Failed to parse response'

            # Track token usage
            tokens_used = 0
            if hasattr(completion, 'usage'):
                tokens_used = completion.usage.total_tokens
                self.total_tokens_used += tokens_used

            response = LLMResponse(
                file_path=request.file_path,
                analysis_type=request.analysis_type,
                findings=findings,
                risk_score=risk_score,
                summary=summary,
                tokens_used=tokens_used,
                analysis_time=time.time() - start_time
            )
            # Enforce response policy (e.g., no external dependency recommendations)
            return self.sanitize_response(response)

        except Exception as e:
            print(f"Cerebras analysis error: {str(e)}")
            return LLMResponse(
                file_path=request.file_path,
                analysis_type=request.analysis_type,
                findings=[],
                risk_score=0.0,
                summary=f"Analysis failed: {str(e)}",
                tokens_used=0,
                analysis_time=time.time() - start_time
            )

    def batch_analyze(self, requests: list[LLMRequest]) -> list[LLMResponse]:
        """Batch analysis with dynamic batching for 64K context
        
        Uses intelligent batching to maximize context window utilization
        while maintaining analysis quality.
        """
        try:
            from .dynamic_batcher import DynamicBatchOptimizer, TokenEstimate
        except ImportError:
            # Fallback to simple batching
            return self._simple_batch_analyze(requests)

        responses = []
        optimizer = DynamicBatchOptimizer(model_context_size=self.max_context_tokens)

        # Convert requests to format expected by optimizer
        file_contents = {req.file_path: req.code_snippet for req in requests}

        # Create fake FileRankingScore objects for compatibility
        class FakeRanking:
            def __init__(self, path, priority):
                self.file_path = path
                self.total_score = priority
                self.importance = type('obj', (object,), {'name': 'HIGH'})()
                self.risk_indicators = []
                self.key_functions = []
                self.external_calls = []
            def get_context_summary(self):
                return {}

        ranked_files = [FakeRanking(req.file_path, req.priority) for req in requests]

        # Get optimized batches
        batches = optimizer.calculate_optimal_batches(
            ranked_files,
            file_contents,
            strategy='adaptive'
        )

        # Process each batch
        for batch in batches:
            batch_requests = []
            for file_data in batch.files:
                # Find matching request
                matching_req = next((r for r in requests if r.file_path == file_data['path'].split('#')[0]), None)
                if matching_req:
                    batch_requests.append(matching_req)

            if batch_requests:
                batch_response = self._process_batch(batch_requests)
                responses.extend(batch_response)

        return responses

    def _simple_batch_analyze(self, requests: list[LLMRequest]) -> list[LLMResponse]:
        """Fallback simple batching if dynamic batcher not available"""
        responses = []
        current_batch = []
        current_tokens = 0

        # Use 50K tokens to leave room for response
        max_batch_tokens = 50000

        for request in requests:
            estimated_tokens = request.estimate_tokens()

            # If adding this request would exceed limit, process current batch
            if current_tokens + estimated_tokens > max_batch_tokens and current_batch:
                batch_response = self._process_batch(current_batch)
                responses.extend(batch_response)
                current_batch = []
                current_tokens = 0

            # Add to current batch
            current_batch.append(request)
            current_tokens += estimated_tokens

        # Process remaining batch
        if current_batch:
            batch_response = self._process_batch(current_batch)
            responses.extend(batch_response)

        return responses

    def _process_batch(self, batch: list[LLMRequest]) -> list[LLMResponse]:
        """Process a batch of requests together"""
        if len(batch) == 1:
            return [self.analyze(batch[0])]

        # Build batch prompt
        code_snippets = [
            {
                'file': req.file_path,
                'code': req.code_snippet[:5000]  # Limit each snippet
            }
            for req in batch
        ]

        system_prompt = self.prompts.get_base_system_prompt()
        user_prompt = self.prompts.build_batch_prompt(code_snippets)

        try:
            completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=4000,
                top_p=0.95
            )

            # Parse batch response
            response_text = completion.choices[0].message.content

            # Try to parse and log if failed
            parsed = self._parse_json_response(response_text)
            if parsed is None and response_text:
                # Filter out test, package, and vendor files from the list
                try:
                    from src.analyzers.shared_constants import should_skip_for_llm
                except ImportError:
                    # Fallback import
                    import sys
                    from pathlib import Path
                    sys.path.append(str(Path(__file__).parent.parent.parent))
                    from src.analyzers.shared_constants import should_skip_for_llm

                important_files = [
                    req.file_path.split('/')[-1]
                    for req in batch
                    if not should_skip_for_llm(req.file_path)
                ]

                # Only log if there are important files in the batch
                if important_files:
                    file_list = ', '.join(important_files[:3])
                    if len(important_files) > 3:
                        file_list += f" and {len(important_files)-3} more"
                    print(f"Failed to parse batch JSON for files: {file_list}")

            batch_results = self._parse_batch_response(response_text, batch)
            # Enforce response policy on each result
            sanitized = [self.sanitize_response(r) for r in batch_results]
            return sanitized

        except Exception as e:
            # Return empty responses for all requests in batch
            return [
                LLMResponse(
                    file_path=req.file_path,
                    analysis_type=req.analysis_type,
                    findings=[],
                    risk_score=0.0,
                    summary=f"Batch analysis failed: {str(e)}",
                    tokens_used=0,
                    analysis_time=0.0
                )
                for req in batch
            ]

    def _map_analysis_to_threat(self, analysis_type: AnalysisType) -> ThreatCategory | None:
        """Map analysis type to threat category"""
        mapping = {
            AnalysisType.PROMPT_INJECTION: ThreatCategory.PROMPT_INJECTION,
            AnalysisType.COMMAND_INJECTION: ThreatCategory.COMMAND_INJECTION,
            AnalysisType.DATA_FLOW: ThreatCategory.DATA_EXFILTRATION,
            AnalysisType.OBFUSCATION: ThreatCategory.OBFUSCATION,
            AnalysisType.SUPPLY_CHAIN: ThreatCategory.SUPPLY_CHAIN,
            AnalysisType.BEHAVIORAL: ThreatCategory.TIME_BOMB,
        }
        return mapping.get(analysis_type)

    # Use shared _parse_json_response from BaseLLMAnalyzer

    def _parse_batch_response(self, response_text: str, batch: list[LLMRequest]) -> list[LLMResponse]:
        """Parse batch response and map to individual requests"""
        responses = []

        parsed = self._parse_json_response(response_text)
        if not parsed or not isinstance(parsed, list):
            # Return empty responses
            return [
                LLMResponse(
                    file_path=req.file_path,
                    analysis_type=req.analysis_type,
                    findings=[],
                    risk_score=0.0,
                    summary="Failed to parse batch response",
                    tokens_used=0,
                    analysis_time=0.0
                )
                for req in batch
            ]

        # Map parsed results to requests
        for i, req in enumerate(batch):
            if i < len(parsed):
                result = parsed[i]
                findings = []

                if 'findings' in result:
                    for finding_data in result['findings']:
                        findings.append(LLMFinding(
                            severity=finding_data.get('severity', 'MEDIUM'),
                            attack_vector=finding_data.get('attack_vector', 'unknown'),
                            description=finding_data.get('description', ''),
                            line_numbers=finding_data.get('line_numbers', []),
                            confidence=finding_data.get('confidence', 0.5),
                            exploitation_scenario=finding_data.get('exploitation_scenario', ''),
                            remediation=finding_data.get('remediation', '')
                        ))

                responses.append(LLMResponse(
                    file_path=req.file_path,
                    analysis_type=req.analysis_type,
                    findings=findings,
                    risk_score=result.get('risk_score', 0.0),
                    summary=result.get('summary', ''),
                    tokens_used=0,
                    analysis_time=0.0
                ))
            else:
                # No result for this request
                responses.append(LLMResponse(
                    file_path=req.file_path,
                    analysis_type=req.analysis_type,
                    findings=[],
                    risk_score=0.0,
                    summary="No result in batch response",
                    tokens_used=0,
                    analysis_time=0.0
                ))

        return responses

    def get_model_info(self) -> dict[str, Any]:
        """Get model information"""
        return {
            "provider": "Cerebras",
            "model": self.model,
            "max_context": self.max_context_tokens,
            "tokens_used": self.total_tokens_used,
            "cost_estimate": f"${self.total_tokens_used * 0.00001:.4f}"  # Rough estimate
        }
