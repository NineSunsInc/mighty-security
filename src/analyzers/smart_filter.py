"""
Smart filtering system for excluding files and adjusting threat severity.
Works with context_analyzer to provide intelligent filtering.
"""

from dataclasses import dataclass

from .context_analyzer import ContextAnalyzer, FileContext


@dataclass
class FilterResult:
    """Result of filtering decision"""
    should_scan: bool
    reason: str
    context: FileContext | None = None
    severity_adjustment: str = "none"


class SmartFilter:
    """Intelligent file filtering based on profiles and context"""

    def __init__(self, profile: str = "production", config_path: str | None = None):
        self.profile = profile
        self.context_analyzer = ContextAnalyzer(config_path)
        self.config = self.context_analyzer.config
        self._validate_profile()
        self.stats = {
            "files_excluded": 0,
            "files_included": 0,
            "adjustments_made": 0,
            "reasons": {}
        }

    def _validate_profile(self):
        """Ensure the profile exists in config"""
        if self.profile not in self.config.get("scan_profiles", {}):
            print(f"Warning: Profile '{self.profile}' not found, using 'production'")
            self.profile = "production"

    def should_scan_file(self, file_path: str, content: str | None = None) -> FilterResult:
        """
        Determine if a file should be scanned and how to adjust severity.
        
        Args:
            file_path: Path to the file
            content: Optional file content for deeper analysis
            
        Returns:
            FilterResult with decision and context
        """
        file_path = str(file_path)

        # First check explicit excludes
        excluded, reason = self.context_analyzer.should_exclude_file(file_path, self.profile)
        if excluded:
            self.stats["files_excluded"] += 1
            self._track_reason(reason)
            return FilterResult(should_scan=False, reason=reason)

        # Get file context
        context = self.context_analyzer.get_file_context(file_path, content)

        # Check if we should exclude based on context
        if self._should_exclude_by_context(context):
            reason = f"Excluded due to context: {context.purpose}"
            self.stats["files_excluded"] += 1
            self._track_reason(reason)
            return FilterResult(
                should_scan=False,
                reason=reason,
                context=context
            )

        # File should be scanned - determine severity adjustment
        severity_adjustment = self.context_analyzer.get_severity_adjustment(context, self.profile)
        if severity_adjustment != "none":
            self.stats["adjustments_made"] += 1

        self.stats["files_included"] += 1
        return FilterResult(
            should_scan=True,
            reason="File included for scanning",
            context=context,
            severity_adjustment=severity_adjustment
        )

    def _should_exclude_by_context(self, context: FileContext) -> bool:
        """Check if context warrants exclusion based on profile settings"""
        profile_config = self.config["scan_profiles"][self.profile]
        adjustments = profile_config.get("severity_adjustments", {})

        # If adjustment is "ignore", exclude the file entirely
        if context.is_test and adjustments.get("test_code") == "ignore":
            return True
        if context.is_example and adjustments.get("example_code") == "ignore":
            return True
        if context.is_generated and adjustments.get("generated_code") == "ignore":
            return True

        return False

    def _track_reason(self, reason: str):
        """Track exclusion reasons for reporting"""
        if reason not in self.stats["reasons"]:
            self.stats["reasons"][reason] = 0
        self.stats["reasons"][reason] += 1

    def adjust_threat_severity(self, threat: dict, context: FileContext) -> dict:
        """
        Adjust threat severity based on context.
        
        Args:
            threat: Threat dictionary with 'severity' and other fields
            context: File context information
            
        Returns:
            Modified threat dictionary
        """
        adjustment = self.context_analyzer.get_severity_adjustment(context, self.profile)

        # Special handling for security tools with obfuscation warnings
        if context.is_security_tool and threat.get("attack_vector") == "OBFUSCATION":
            # Security tools often have names like "analyzer", "detector" which trigger false positives
            if "variable" in threat.get("description", "").lower():
                threat["severity"] = "LOW"
                threat["original_severity"] = threat.get("severity", "MEDIUM")
                threat["adjustment_reason"] = "Security tool variable naming pattern"
                adjustment = "handled"  # Mark as handled

        if adjustment == "none" or adjustment == "handled":
            # Still add context information
            threat["file_context"] = {
                "purpose": context.purpose,
                "is_test": context.is_test,
                "is_example": context.is_example,
                "is_security_tool": context.is_security_tool,
                "is_generated": context.is_generated
            }
            if adjustment != "handled":
                return threat

        # Get the mapping if not handled
        if adjustment != "handled" and adjustment in self.config.get("severity_mappings", {}):
            mapping = self.config["severity_mappings"][adjustment]
            original_severity = threat.get("severity", "MEDIUM")

            if original_severity in mapping:
                new_severity = mapping[original_severity]

                if new_severity == "IGNORE":
                    # Mark threat as ignored
                    threat["ignored"] = True
                    threat["ignore_reason"] = f"Severity adjustment: {context.purpose}"
                else:
                    threat["severity"] = new_severity
                    threat["original_severity"] = original_severity
                    threat["adjustment_reason"] = f"Context: {context.purpose}"

        # Add context information to threat
        threat["file_context"] = {
            "purpose": context.purpose,
            "is_test": context.is_test,
            "is_example": context.is_example,
            "is_security_tool": context.is_security_tool,
            "is_generated": context.is_generated
        }

        return threat

    def filter_threats(self, threats: list[dict], file_path: str, content: str | None = None) -> list[dict]:
        """
        Filter and adjust threats for a file.
        
        Args:
            threats: List of threat dictionaries
            file_path: Path to the file
            content: Optional file content
            
        Returns:
            Filtered and adjusted list of threats
        """
        # Get file context
        context = self.context_analyzer.get_file_context(file_path, content)

        # Adjust each threat
        adjusted_threats = []
        for threat in threats:
            adjusted = self.adjust_threat_severity(threat.copy(), context)

            # Skip ignored threats
            if not adjusted.get("ignored", False):
                adjusted_threats.append(adjusted)

        return adjusted_threats

    def get_profile_info(self) -> dict:
        """Get information about the current profile"""
        if self.profile not in self.config.get("scan_profiles", {}):
            return {"error": "Profile not found"}

        profile_config = self.config["scan_profiles"][self.profile]
        return {
            "name": self.profile,
            "description": profile_config.get("description", "No description"),
            "exclude_count": len(profile_config.get("exclude_paths", [])),
            "adjustments": profile_config.get("severity_adjustments", {}),
            "context_aware": profile_config.get("context_aware", False)
        }

    def get_stats(self) -> dict:
        """Get filtering statistics"""
        return {
            "profile": self.profile,
            "files_excluded": self.stats["files_excluded"],
            "files_included": self.stats["files_included"],
            "adjustments_made": self.stats["adjustments_made"],
            "top_exclusion_reasons": sorted(
                self.stats["reasons"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }

    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            "files_excluded": 0,
            "files_included": 0,
            "adjustments_made": 0,
            "reasons": {}
        }


class BatchFilter:
    """Filter for processing multiple files efficiently"""

    def __init__(self, profile: str = "production"):
        self.filter = SmartFilter(profile)

    def filter_file_list(self, file_paths: list[str]) -> tuple[list[str], dict]:
        """
        Filter a list of file paths.
        
        Args:
            file_paths: List of file paths to filter
            
        Returns:
            Tuple of (files_to_scan, exclusion_report)
        """
        files_to_scan = []
        exclusion_report = {
            "total_files": len(file_paths),
            "excluded_files": [],
            "included_files": []
        }

        for file_path in file_paths:
            result = self.filter.should_scan_file(file_path)

            if result.should_scan:
                files_to_scan.append(file_path)
                exclusion_report["included_files"].append(file_path)
            else:
                exclusion_report["excluded_files"].append({
                    "path": file_path,
                    "reason": result.reason
                })

        exclusion_report["scan_count"] = len(files_to_scan)
        exclusion_report["excluded_count"] = len(exclusion_report["excluded_files"])

        return files_to_scan, exclusion_report
