#!/usr/bin/env python3
"""
Dynamic Batching System for LLM Analysis
Maximizes context window utilization with intelligent batching
"""

from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path
import tiktoken
import math

@dataclass
class TokenEstimate:
    """Accurate token estimation for different content types"""
    file_path: str
    content: str
    estimated_tokens: int
    actual_tokens: Optional[int] = None
    
    # Content characteristics
    code_density: float = 0.0  # 0-1, higher = more code
    comment_ratio: float = 0.0  # Ratio of comments to code
    avg_line_length: float = 0.0
    
    def refine_estimate(self, encoding_model: str = "cl100k_base"):
        """Use tiktoken for accurate token counting"""
        try:
            enc = tiktoken.get_encoding(encoding_model)
            self.actual_tokens = len(enc.encode(self.content))
        except:
            # Fallback to refined heuristic
            # More accurate than simple /4 division
            chars = len(self.content)
            lines = self.content.count('\n')
            
            # Base estimate
            base_tokens = chars / 3.5  # Better average for code
            
            # Adjust for code density
            if self.code_density > 0.7:
                # Dense code has more tokens per char
                base_tokens *= 1.1
            elif self.code_density < 0.3:
                # Comments/docs have fewer tokens
                base_tokens *= 0.9
            
            # Adjust for line structure
            if self.avg_line_length < 40:
                # Short lines = more newline tokens
                base_tokens += lines * 0.5
            
            self.actual_tokens = int(base_tokens)
        
        return self.actual_tokens or self.estimated_tokens

@dataclass 
class DynamicBatch:
    """A batch of files optimized for context window"""
    files: List[Dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    priority_score: float = 0.0
    batch_id: str = ""
    
    # Batch characteristics
    has_critical: bool = False
    has_entry_points: bool = False
    coverage_score: float = 0.0  # How well this batch covers the codebase
    
    def add_file(self, file_data: Dict[str, Any], tokens: int):
        """Add a file to this batch"""
        self.files.append(file_data)
        self.total_tokens += tokens
        
        # Update batch characteristics
        if file_data.get('importance') == 'CRITICAL':
            self.has_critical = True
        if 'main' in file_data['path'] or 'index' in file_data['path']:
            self.has_entry_points = True
        
        # Update priority score (average of file priorities)
        total_priority = self.priority_score * (len(self.files) - 1)
        self.priority_score = (total_priority + file_data.get('score', 0)) / len(self.files)
    
    def can_fit(self, tokens: int, max_tokens: int) -> bool:
        """Check if more tokens can fit in this batch"""
        return (self.total_tokens + tokens) <= max_tokens
    
    def get_summary(self) -> Dict[str, Any]:
        """Get batch summary for logging"""
        return {
            'batch_id': self.batch_id,
            'file_count': len(self.files),
            'total_tokens': self.total_tokens,
            'priority': self.priority_score,
            'has_critical': self.has_critical,
            'files': [f['path'] for f in self.files[:5]]  # First 5 for brevity
        }

class DynamicBatchOptimizer:
    """Optimizes file batching for maximum LLM efficiency"""
    
    def __init__(self, model_context_size: int = 64000):
        """
        Initialize the dynamic batcher
        
        Args:
            model_context_size: Total context window (default 64K for Cerebras)
        """
        self.model_context_size = model_context_size
        # Reserve space for system prompt and response
        self.usable_context = int(model_context_size * 0.75)  # Use 75% for input
        
        # Batching strategies
        self.strategies = {
            'priority': self._batch_by_priority,
            'related': self._batch_by_relationship,
            'balanced': self._batch_balanced,
            'adaptive': self._batch_adaptive
        }
        
    def calculate_optimal_batches(
        self,
        ranked_files: List[Any],  # FileRankingScore objects
        file_contents: Dict[str, str],
        strategy: str = 'adaptive'
    ) -> List[DynamicBatch]:
        """
        Calculate optimal batches based on context window and strategy
        
        Args:
            ranked_files: List of FileRankingScore objects (already ranked)
            file_contents: Map of file_path -> content
            strategy: Batching strategy to use
        
        Returns:
            List of optimized batches
        """
        # First, get accurate token counts
        token_estimates = []
        for file_score in ranked_files:
            if file_score.file_path not in file_contents:
                continue
                
            content = file_contents[file_score.file_path]
            estimate = TokenEstimate(
                file_path=file_score.file_path,
                content=content,
                estimated_tokens=len(content) // 4  # Initial estimate
            )
            
            # Calculate content characteristics
            lines = content.split('\n')
            estimate.avg_line_length = sum(len(l) for l in lines) / max(len(lines), 1)
            
            # Detect code vs comments
            comment_lines = sum(1 for l in lines if l.strip().startswith(('#', '//', '/*', '*')))
            estimate.comment_ratio = comment_lines / max(len(lines), 1)
            estimate.code_density = 1.0 - estimate.comment_ratio
            
            # Refine the estimate
            estimate.refine_estimate()
            
            token_estimates.append((file_score, estimate))
        
        # Apply the selected strategy
        strategy_func = self.strategies.get(strategy, self._batch_adaptive)
        return strategy_func(token_estimates)
    
    def _batch_adaptive(self, token_estimates: List[Tuple[Any, TokenEstimate]]) -> List[DynamicBatch]:
        """
        Adaptive batching that adjusts based on content characteristics
        
        This is the recommended strategy that:
        1. Prioritizes critical files
        2. Groups related files
        3. Maximizes context utilization
        4. Maintains good coverage
        """
        batches = []
        current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
        
        # Sort by priority but keep related files together
        sorted_estimates = self._group_related_files(token_estimates)
        
        # Adaptive token limit based on content
        for file_score, estimate in sorted_estimates:
            tokens = estimate.actual_tokens or estimate.estimated_tokens
            
            # Determine batch size limit based on content type
            if current_batch.has_critical:
                # Critical files get more room
                batch_limit = self.usable_context * 0.8
            else:
                # Normal files can pack tighter
                batch_limit = self.usable_context * 0.9
            
            # Check if file fits in current batch
            if not current_batch.can_fit(tokens, batch_limit):
                # Start new batch if current has content
                if current_batch.files:
                    batches.append(current_batch)
                    current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
            
            # Skip files too large for any batch
            if tokens > batch_limit:
                # Split large files into chunks
                chunks = self._split_large_file(estimate, batch_limit)
                for chunk in chunks:
                    if current_batch.can_fit(chunk['tokens'], batch_limit):
                        current_batch.add_file(chunk, chunk['tokens'])
                    else:
                        if current_batch.files:
                            batches.append(current_batch)
                            current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
                        current_batch.add_file(chunk, chunk['tokens'])
            else:
                # Add file to batch
                file_data = {
                    'path': file_score.file_path,
                    'content': estimate.content[:10000],  # Limit content size
                    'score': file_score.total_score,
                    'importance': file_score.importance.name,
                    'tokens': tokens,
                    'context': file_score.get_context_summary()
                }
                current_batch.add_file(file_data, tokens)
        
        # Add final batch
        if current_batch.files:
            batches.append(current_batch)
        
        return batches
    
    def _batch_by_priority(self, token_estimates: List[Tuple[Any, TokenEstimate]]) -> List[DynamicBatch]:
        """Simple priority-based batching"""
        batches = []
        current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
        
        # Already sorted by priority
        for file_score, estimate in token_estimates:
            tokens = estimate.actual_tokens or estimate.estimated_tokens
            
            if not current_batch.can_fit(tokens, self.usable_context):
                if current_batch.files:
                    batches.append(current_batch)
                    current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
            
            if tokens <= self.usable_context:
                file_data = {
                    'path': file_score.file_path,
                    'content': estimate.content[:10000],
                    'score': file_score.total_score,
                    'importance': file_score.importance.name,
                    'tokens': tokens
                }
                current_batch.add_file(file_data, tokens)
        
        if current_batch.files:
            batches.append(current_batch)
        
        return batches
    
    def _batch_by_relationship(self, token_estimates: List[Tuple[Any, TokenEstimate]]) -> List[DynamicBatch]:
        """Group related files together (same directory, imports, etc.)"""
        # Group files by directory
        directory_groups = {}
        for file_score, estimate in token_estimates:
            dir_path = str(Path(file_score.file_path).parent)
            if dir_path not in directory_groups:
                directory_groups[dir_path] = []
            directory_groups[dir_path].append((file_score, estimate))
        
        batches = []
        current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
        
        # Process each directory group
        for dir_path, files in sorted(directory_groups.items(), 
                                     key=lambda x: max(f[0].total_score for f in x[1]), 
                                     reverse=True):
            for file_score, estimate in files:
                tokens = estimate.actual_tokens or estimate.estimated_tokens
                
                if not current_batch.can_fit(tokens, self.usable_context):
                    if current_batch.files:
                        batches.append(current_batch)
                        current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
                
                if tokens <= self.usable_context:
                    file_data = {
                        'path': file_score.file_path,
                        'content': estimate.content[:10000],
                        'score': file_score.total_score,
                        'importance': file_score.importance.name,
                        'tokens': tokens,
                        'directory': dir_path
                    }
                    current_batch.add_file(file_data, tokens)
        
        if current_batch.files:
            batches.append(current_batch)
        
        return batches
    
    def _batch_balanced(self, token_estimates: List[Tuple[Any, TokenEstimate]]) -> List[DynamicBatch]:
        """Balance between priority and coverage"""
        # Mix high and low priority files for better coverage
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for file_score, estimate in token_estimates:
            if file_score.total_score >= 0.7:
                high_priority.append((file_score, estimate))
            elif file_score.total_score >= 0.4:
                medium_priority.append((file_score, estimate))
            else:
                low_priority.append((file_score, estimate))
        
        batches = []
        current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
        
        # Interleave priorities for balanced batches
        all_files = []
        while high_priority or medium_priority or low_priority:
            if high_priority:
                all_files.append(high_priority.pop(0))
            if medium_priority:
                all_files.append(medium_priority.pop(0))
            if low_priority and len(all_files) % 3 == 0:  # Add low priority every 3rd file
                all_files.append(low_priority.pop(0))
        
        for file_score, estimate in all_files:
            tokens = estimate.actual_tokens or estimate.estimated_tokens
            
            if not current_batch.can_fit(tokens, self.usable_context):
                if current_batch.files:
                    batches.append(current_batch)
                    current_batch = DynamicBatch(batch_id=f"batch_{len(batches)}")
            
            if tokens <= self.usable_context:
                file_data = {
                    'path': file_score.file_path,
                    'content': estimate.content[:10000],
                    'score': file_score.total_score,
                    'importance': file_score.importance.name,
                    'tokens': tokens
                }
                current_batch.add_file(file_data, tokens)
        
        if current_batch.files:
            batches.append(current_batch)
        
        return batches
    
    def _group_related_files(self, token_estimates: List[Tuple[Any, TokenEstimate]]) -> List[Tuple[Any, TokenEstimate]]:
        """Group related files while maintaining priority order"""
        # Simple grouping by directory proximity
        grouped = []
        seen_dirs = set()
        
        # First pass: high priority files
        for file_score, estimate in token_estimates:
            if file_score.total_score >= 0.7:
                grouped.append((file_score, estimate))
                seen_dirs.add(str(Path(file_score.file_path).parent))
        
        # Second pass: files from same directories
        for file_score, estimate in token_estimates:
            if (file_score, estimate) not in grouped:
                if str(Path(file_score.file_path).parent) in seen_dirs:
                    grouped.append((file_score, estimate))
        
        # Third pass: remaining files by priority
        for file_score, estimate in token_estimates:
            if (file_score, estimate) not in grouped:
                grouped.append((file_score, estimate))
        
        return grouped
    
    def _split_large_file(self, estimate: TokenEstimate, max_tokens: int) -> List[Dict[str, Any]]:
        """Split large files into analyzable chunks"""
        chunks = []
        content = estimate.content
        
        # Calculate chunk size in characters (rough estimate)
        chars_per_token = len(content) / (estimate.actual_tokens or estimate.estimated_tokens)
        chunk_size_chars = int(max_tokens * chars_per_token * 0.8)  # 80% to be safe
        
        # Split content into chunks
        lines = content.split('\n')
        current_chunk = []
        current_size = 0
        
        for line in lines:
            line_size = len(line) + 1  # +1 for newline
            if current_size + line_size > chunk_size_chars and current_chunk:
                # Save current chunk
                chunk_content = '\n'.join(current_chunk)
                chunks.append({
                    'path': f"{estimate.file_path}#chunk{len(chunks)}",
                    'content': chunk_content,
                    'tokens': len(chunk_content) // 4,  # Rough estimate
                    'is_chunk': True,
                    'chunk_index': len(chunks),
                    'total_chunks': 0  # Will be updated
                })
                current_chunk = [line]
                current_size = line_size
            else:
                current_chunk.append(line)
                current_size += line_size
        
        # Add final chunk
        if current_chunk:
            chunk_content = '\n'.join(current_chunk)
            chunks.append({
                'path': f"{estimate.file_path}#chunk{len(chunks)}",
                'content': chunk_content,
                'tokens': len(chunk_content) // 4,
                'is_chunk': True,
                'chunk_index': len(chunks),
                'total_chunks': len(chunks) + 1
            })
        
        # Update total chunks count
        for chunk in chunks:
            chunk['total_chunks'] = len(chunks)
        
        return chunks
    
    def estimate_total_batches(self, file_count: int, avg_file_size: int = 2000) -> int:
        """Estimate how many batches will be needed"""
        avg_tokens_per_file = avg_file_size // 4
        total_tokens = file_count * avg_tokens_per_file
        return math.ceil(total_tokens / self.usable_context)
    
    def get_batch_stats(self, batches: List[DynamicBatch]) -> Dict[str, Any]:
        """Get statistics about the batching"""
        total_files = sum(len(b.files) for b in batches)
        total_tokens = sum(b.total_tokens for b in batches)
        
        return {
            'total_batches': len(batches),
            'total_files': total_files,
            'total_tokens': total_tokens,
            'avg_files_per_batch': total_files / max(len(batches), 1),
            'avg_tokens_per_batch': total_tokens / max(len(batches), 1),
            'context_utilization': total_tokens / (len(batches) * self.usable_context) if batches else 0,
            'batches_with_critical': sum(1 for b in batches if b.has_critical),
            'priority_distribution': {
                'high': sum(1 for b in batches if b.priority_score >= 0.7),
                'medium': sum(1 for b in batches if 0.4 <= b.priority_score < 0.7),
                'low': sum(1 for b in batches if b.priority_score < 0.4)
            }
        }