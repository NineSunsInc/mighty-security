#!/usr/bin/env python3
"""
LLM Integration for Main Analyzer
Coordinates LLM analysis with ranking and aggregation
"""

import os
from pathlib import Path
from typing import Any

from .base_analyzer import AnalysisType, LLMRequest
from .cerebras_analyzer import CerebrasAnalyzer
from .context_optimizer import AnalysisTracker, FileImportance, SmartFileRanker

# Try to import semantic analyzer (new path)
try:
    from src.semantics.semantic_security_analyzer import SemanticSecurityAnalyzer
    HAS_ML_ANALYZER = True
except ImportError:
    HAS_ML_ANALYZER = False

class LLMAnalysisCoordinator:
    """Coordinates LLM and ML analysis with smart ranking"""

    def __init__(self, llm_provider: str = "cerebras", api_key: str | None = None):
        self.ranker = SmartFileRanker()
        self.tracker = None

        # Check for debug mode from environment
        debug = os.environ.get('LLM_DEBUG', '').lower() == 'true'

        # Initialize LLM analyzer with debug flag; fall back to no-op if no API key
        if llm_provider == "cerebras":
            if not api_key and not os.environ.get("CEREBRAS_API_KEY"):
                # Offline/no-op analyzer
                class _NoopAnalyzer:
                    max_context_tokens = 8000
                    def analyze(self, request):
                        return type("LLMResult", (), {
                            'file_path': request.file_path,
                            'findings': [],
                            'risk_score': 0.0,
                        })()
                    def batch_analyze(self, requests):
                        return [self.analyze(r) for r in requests]
                self.llm_analyzer = _NoopAnalyzer()
            else:
                self.llm_analyzer = CerebrasAnalyzer(api_key, debug=debug)
        else:
            # Future: Add OpenAI, Anthropic, etc.
            self.llm_analyzer = CerebrasAnalyzer(api_key, debug=debug)

        # Initialize semantic analyzer if available
        self.ml_analyzer = SemanticSecurityAnalyzer() if HAS_ML_ANALYZER else None

    async def analyze_with_llm_and_ml(
        self,
        repo_path: Path,
        static_results: dict[str, Any],
        semantic_graph: Any | None = None,
        max_files: int | None = None,  # None = dynamic based on context
        use_dynamic_batching: bool = True
    ) -> dict[str, Any]:
        """Perform coordinated LLM and ML analysis
        
        Args:
            repo_path: Path to repository
            static_results: Results from static analysis
            semantic_graph: Optional dependency graph
            max_files: Optional limit on files (None = smart selection based on context)
            use_dynamic_batching: Use dynamic batching to maximize context usage
        """

        results = {
            'llm_analysis': {},
            'ml_analysis': {},
            'aggregate_assessment': {},
            'individual_threats': [],
            'combined_risk_score': 0.0
        }

        # Get file contents
        file_contents = self._load_file_contents(repo_path, static_results)

        # Rank files for analysis with dynamic selection
        if use_dynamic_batching and max_files is None:
            # Let the ranker decide based on importance scores
            ranked_files = self.ranker.rank_files_for_analysis(
                file_contents,
                static_results.get('threats_found', []),
                semantic_graph,
                max_files=None,  # No limit, filter by score
                min_score_threshold=0.05  # Only exclude very low scores
            )
        else:
            # Use specified limit or default
            ranked_files = self.ranker.rank_files_for_analysis(
                file_contents,
                static_results.get('threats_found', []),
                semantic_graph,
                max_files=max_files or 50  # Default to 50 if specified
            )

        # Initialize tracker
        self.tracker = AnalysisTracker(total_files=len(ranked_files))

        # Use dynamic batching if enabled
        if use_dynamic_batching:
            llm_findings = await self._batch_analyze_with_dynamic(
                ranked_files,
                file_contents,
                static_results
            )
            ml_findings = []
        else:
            # Original sequential analysis
            llm_findings = []
            ml_findings = []

        for ranking in ranked_files:
            # Skip minimal importance files if we're over budget
            if ranking.importance == FileImportance.MINIMAL and self.tracker.analyzed_files > 10:
                continue

            file_path = ranking.file_path
            content = file_contents.get(file_path, "")

            # Prepare context for LLM
            context = ranking.get_context_summary()

            # LLM Analysis
            if self.llm_analyzer and content:
                llm_result = await self._analyze_file_with_llm(
                    file_path,
                    content,
                    context,
                    ranking.importance
                )
                if llm_result:
                    llm_findings.append(llm_result)
                    self.tracker.add_file_result(
                        file_path,
                        llm_result.findings,
                        llm_result.risk_score
                    )

            # ML Analysis (if available)
            if self.ml_analyzer and HAS_ML_ANALYZER and content:
                ml_result = await self._analyze_file_with_ml(file_path, content)
                if ml_result:
                    ml_findings.append(ml_result)

        # Aggregate results
        results['llm_analysis'] = self._aggregate_llm_results(llm_findings)
        results['ml_analysis'] = self._aggregate_ml_results(ml_findings)

        # Individual threat assessment
        results['individual_threats'] = self._assess_individual_threats(
            llm_findings,
            ml_findings,
            static_results.get('threats_found', [])
        )

        # Combined risk assessment
        results['combined_risk_score'] = self._calculate_combined_risk(
            results['llm_analysis'],
            results['ml_analysis'],
            static_results
        )

        # Final aggregate assessment
        results['aggregate_assessment'] = {
            'files_analyzed': self.tracker.analyzed_files,
            'critical_findings': len(self.tracker.critical_findings),
            'llm_risk_score': results['llm_analysis'].get('aggregate_risk', 0),
            'ml_risk_score': results['ml_analysis'].get('aggregate_risk', 0),
            'combined_risk': results['combined_risk_score'],
            'verdict': self._determine_verdict(results['combined_risk_score']),
            'confidence': self._calculate_confidence(llm_findings, ml_findings)
        }

        return results

    async def _batch_analyze_with_dynamic(
        self,
        ranked_files: list[Any],
        file_contents: dict[str, str],
        static_results: dict[str, Any]
    ) -> list[Any]:
        """Batch analyze files using dynamic batching"""
        try:
            from .dynamic_batcher import DynamicBatchOptimizer
        except ImportError:
            # Fallback to sequential if dynamic batcher not available
            return await self._sequential_analyze(ranked_files, file_contents)

        optimizer = DynamicBatchOptimizer(model_context_size=self.llm_analyzer.max_context_tokens)

        # Get optimized batches
        batches = optimizer.calculate_optimal_batches(
            ranked_files,
            file_contents,
            strategy='adaptive'
        )

        # Prepare batch requests
        all_requests = []
        for batch in batches:
            batch_requests = []
            for file_data in batch.files:
                # Create LLM request for each file
                file_path = file_data['path'].split('#')[0]  # Handle chunked files
                context = file_data.get('context', {})

                request = LLMRequest(
                    file_path=file_path,
                    code_snippet=file_data['content'],
                    analysis_type=self._determine_analysis_type(context),
                    context=context,
                    priority=file_data.get('score', 0.5),
                    max_tokens=2000 if file_data.get('importance') == 'CRITICAL' else 1000
                )
                batch_requests.append(request)

            if batch_requests:
                all_requests.extend(batch_requests)

        # Process all requests through batch analyzer
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None,
                self.llm_analyzer.batch_analyze,
                all_requests
            )

            # Update tracker with results
            for result in results:
                if result and hasattr(result, 'findings'):
                    self.tracker.add_file_result(
                        result.file_path,
                        result.findings,
                        result.risk_score
                    )

            return results

        except Exception as e:
            print(f"Batch analysis failed: {e}")
            # Fallback to sequential
            return await self._sequential_analyze(ranked_files, file_contents)

    async def _sequential_analyze(
        self,
        ranked_files: list[Any],
        file_contents: dict[str, str]
    ) -> list[Any]:
        """Fallback sequential analysis"""
        findings = []
        for ranking in ranked_files[:50]:  # Limit to 50 files for sequential
            if ranking.importance == FileImportance.MINIMAL and self.tracker.analyzed_files > 10:
                continue

            file_path = ranking.file_path
            content = file_contents.get(file_path, "")

            if content:
                result = await self._analyze_file_with_llm(
                    file_path,
                    content,
                    ranking.get_context_summary(),
                    ranking.importance
                )
                if result:
                    findings.append(result)

        return findings

    async def _analyze_file_with_llm(
        self,
        file_path: str,
        content: str,
        context: dict,
        importance: FileImportance
    ) -> Any | None:
        """Analyze single file with LLM"""

        # Determine analysis type based on context
        analysis_type = self._determine_analysis_type(context)

        # Create LLM request
        request = LLMRequest(
            file_path=file_path,
            code_snippet=content[:8000],  # Limit size
            analysis_type=analysis_type,
            context=context,
            priority=importance.value / 5.0,  # Normalize to 0-1
            max_tokens=2000 if importance == FileImportance.CRITICAL else 1000
        )

        try:
            # Run sync method in executor for async compatibility
            import asyncio
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self.llm_analyzer.analyze, request)
        except Exception as e:
            print(f"LLM analysis failed for {file_path}: {e}")
            return None

    async def _analyze_file_with_ml(self, file_path: str, content: str) -> Any | None:
        """Analyze file with ML model"""
        if not self.ml_analyzer:
            return None

        try:
            # Prepare tool config for semantic analyzer (async)
            tool_config = {
                'name': Path(file_path).stem,
                'description': f'File: {file_path}',
                'code': content
            }
            result = await self.ml_analyzer.analyze(tool_config)
            return {
                'file_path': file_path,
                'analysis': result
            }
        except Exception as e:
            print(f"ML analysis failed for {file_path}: {e}")
            return None

    def _aggregate_llm_results(self, findings: list[Any]) -> dict[str, Any]:
        """Aggregate LLM analysis results"""
        if not findings:
            return {'aggregate_risk': 0.0, 'total_findings': 0}

        total_risk = 0.0
        all_findings = []
        critical_count = 0
        high_count = 0

        for result in findings:
            if hasattr(result, 'risk_score'):
                total_risk += result.risk_score

            if hasattr(result, 'findings'):
                for finding in result.findings:
                    all_findings.append(finding)
                    if finding.severity == 'CRITICAL':
                        critical_count += 1
                    elif finding.severity == 'HIGH':
                        high_count += 1

        return {
            'aggregate_risk': total_risk / len(findings) if findings else 0,
            'total_findings': len(all_findings),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'findings_by_type': self._group_findings_by_type(all_findings)
        }

    def _aggregate_ml_results(self, findings: list[Any]) -> dict[str, Any]:
        """Aggregate ML analysis results"""
        if not findings:
            return {'aggregate_risk': 0.0, 'total_threats': 0}

        total_risk = 0.0
        all_threats = []

        for result in findings:
            if 'analysis' in result:
                analysis = result['analysis']
                if hasattr(analysis, 'risk_score'):
                    total_risk += analysis.risk_score
                if hasattr(analysis, 'threat_indicators'):
                    all_threats.extend(analysis.threat_indicators)

        return {
            'aggregate_risk': total_risk / len(findings) if findings else 0,
            'total_threats': len(all_threats),
            'threat_types': self._group_threats_by_type(all_threats)
        }

    def _assess_individual_threats(
        self,
        llm_findings: list[Any],
        ml_findings: list[Any],
        static_threats: list[Any]
    ) -> list[dict[str, Any]]:
        """Assess individual threats from all sources"""

        threats = []

        # Process LLM findings
        for llm_result in llm_findings:
            if hasattr(llm_result, 'findings'):
                for finding in llm_result.findings:
                    threats.append({
                        'source': 'llm',
                        'file': llm_result.file_path,
                        'type': finding.attack_vector,
                        'severity': finding.severity,
                        'confidence': finding.confidence,
                        'description': finding.description
                    })

        # Process ML findings
        for ml_result in ml_findings:
            if 'analysis' in ml_result:
                analysis = ml_result['analysis']
                if hasattr(analysis, 'threat_indicators'):
                    for threat in analysis.threat_indicators:
                        threats.append({
                            'source': 'ml',
                            'file': ml_result['file_path'],
                            'type': str(threat.type),
                            'severity': self._ml_severity_to_string(threat.severity),
                            'confidence': threat.confidence,
                            'description': ', '.join(threat.evidence)
                        })

        # Process static threats
        for static_threat in static_threats[:20]:  # Limit to top 20
            threats.append({
                'source': 'static',
                'file': getattr(static_threat, 'file_path', 'unknown'),
                'type': str(getattr(static_threat, 'attack_vector', 'unknown')),
                'severity': str(getattr(static_threat, 'severity', 'MEDIUM')),
                'confidence': getattr(static_threat, 'confidence', 0.5),
                'description': getattr(static_threat, 'description', '')
            })

        # Sort by severity and confidence
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        threats.sort(key=lambda x: (
            severity_order.get(x['severity'], 0),
            x['confidence']
        ), reverse=True)

        return threats

    def _calculate_combined_risk(
        self,
        llm_analysis: dict,
        ml_analysis: dict,
        static_results: dict
    ) -> float:
        """Calculate combined risk score from all sources"""

        # Weight different analysis types
        weights = {
            'llm': 0.35,
            'ml': 0.35,
            'static': 0.30
        }

        llm_risk = llm_analysis.get('aggregate_risk', 0)
        ml_risk = ml_analysis.get('aggregate_risk', 0)

        # Calculate static risk from threat score
        static_risk = static_results.get('threat_score', 0)

        combined = (
            weights['llm'] * llm_risk +
            weights['ml'] * ml_risk +
            weights['static'] * static_risk
        )

        return min(1.0, combined)

    def _determine_verdict(self, risk_score: float) -> str:
        """Determine final verdict based on risk score"""
        if risk_score >= 0.8:
            return "CRITICAL - Do not use"
        elif risk_score >= 0.6:
            return "HIGH RISK - Review required"
        elif risk_score >= 0.4:
            return "MODERATE RISK - Use with caution"
        elif risk_score >= 0.2:
            return "LOW RISK - Monitor usage"
        else:
            return "MINIMAL RISK - Safe to use"

    def _calculate_confidence(self, llm_findings: list, ml_findings: list) -> float:
        """Calculate confidence in the assessment"""
        factors = []

        # More analysis = higher confidence
        if llm_findings:
            factors.append(min(1.0, len(llm_findings) / 10))
        if ml_findings:
            factors.append(min(1.0, len(ml_findings) / 10))

        # Agreement between analyzers = higher confidence
        if llm_findings and ml_findings:
            # Check if they agree on risk level
            llm_high_risk = any(
                f.risk_score > 0.7 for f in llm_findings
                if hasattr(f, 'risk_score')
            )
            ml_high_risk = any(
                f.get('analysis', {}).risk_score > 0.7 for f in ml_findings
                if 'analysis' in f and hasattr(f['analysis'], 'risk_score')
            )
            if llm_high_risk == ml_high_risk:
                factors.append(0.9)
            else:
                factors.append(0.6)

        return sum(factors) / len(factors) if factors else 0.5

    def _determine_analysis_type(self, context: dict) -> AnalysisType:
        """Determine best analysis type based on context"""
        risks = context.get('risks', [])

        if 'prompt_injection' in str(risks):
            return AnalysisType.PROMPT_INJECTION
        elif 'command_injection' in str(risks):
            return AnalysisType.COMMAND_INJECTION
        elif 'data_exfiltration' in str(risks):
            return AnalysisType.DATA_FLOW
        elif context.get('scores', {}).get('obfuscation', 0) > 0.5:
            return AnalysisType.OBFUSCATION
        else:
            return AnalysisType.DEEP_SCAN

    def _load_file_contents(self, repo_path: Path, static_results: dict) -> dict[str, str]:
        """Load contents of analyzed files"""
        contents = {}

        # Get list of files from static results - prioritize files with threats
        files_analyzed = set()
        for threat in static_results.get('threats_found', []):
            file_path = getattr(threat, 'file_path', None) or threat.get('file_path')
            if file_path and file_path != 'git_history':
                files_analyzed.add(file_path)

        # If no threats or too few files, scan for code files
        if len(files_analyzed) < 5:
            try:
                from src.analyzers.shared_constants import get_scannable_files
            except ImportError:
                # Try relative import
                import sys
                from pathlib import Path
                sys.path.append(str(Path(__file__).parent.parent))
                from shared_constants import get_scannable_files
            # Get some code files to analyze
            code_files = get_scannable_files(repo_path, include_configs=False, include_security=False)
            for file_path in code_files[:100]:  # Increase limit to 100 files
                rel_path = str(file_path.relative_to(repo_path))
                files_analyzed.add(rel_path)

        # Load contents
        for file_path in files_analyzed:
            full_path = repo_path / file_path
            if full_path.exists():
                try:
                    # Limit file size to avoid huge files
                    file_size = full_path.stat().st_size
                    if file_size < 100 * 1024:  # 100KB limit for LLM
                        with open(full_path, encoding='utf-8', errors='ignore') as f:
                            contents[file_path] = f.read()
                except Exception:
                    pass

        return contents

    def _group_findings_by_type(self, findings: list) -> dict[str, int]:
        """Group findings by attack type"""
        by_type = {}
        for finding in findings:
            attack_type = finding.attack_vector if hasattr(finding, 'attack_vector') else 'unknown'
            by_type[attack_type] = by_type.get(attack_type, 0) + 1
        return by_type

    def _group_threats_by_type(self, threats: list) -> dict[str, int]:
        """Group ML threats by type"""
        by_type = {}
        for threat in threats:
            threat_type = str(threat.type) if hasattr(threat, 'type') else 'unknown'
            by_type[threat_type] = by_type.get(threat_type, 0) + 1
        return by_type

    def _ml_severity_to_string(self, severity: float) -> str:
        """Convert ML severity score to string"""
        if severity >= 0.8:
            return 'CRITICAL'
        elif severity >= 0.6:
            return 'HIGH'
        elif severity >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
