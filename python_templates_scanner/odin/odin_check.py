"""
OdinCheck - Base class for all vulnerability checks
"""

import os
from typing import List, Union, Any
from odin.check_target import CheckTarget
from odin.check_result import CheckResult


class OdinCheck:
    """Base class for all vulnerability checks."""
    
    # Class-level storage for warmup data
    _warmup_data = {}
    
    # Check metadata - should be overridden by subclasses
    name: str = None
    severity: str = None
    description: str = None
    poc: str = None
    
    def __init__(self, mode: str, target: CheckTarget):
        """
        Initialize a OdinCheck.
        
        Args:
            mode: Execution mode (e.g., 'scan', 'test')
            target: CheckTarget instance representing the target to check
        """
        self.mode = mode
        self.target = target
        
        # Set convenience attributes for backward compatibility
        # (some existing code uses self.host and self.port)
        self.host = target.ip
        self.port = target.port
    
    def check(self) -> List[Union[CheckResult, dict]]:
        """
        Perform the vulnerability check.
        
        This method should be overridden by subclasses.
        
        Returns:
            List of CheckResult objects or dictionaries representing findings
        """
        raise NotImplementedError("Subclasses must implement the check() method")
    
    def get_oob(self) -> str:
        """
        Get an out-of-band (OOB) server address for testing.
        
        This is typically used for XXE, SSRF, or other out-of-band testing.
        The address is read from the ODIN_OOB environment variable, or defaults
        to a common OOB testing service.
        
        Returns:
            OOB server address (IP or domain)
        """
        # Try to get from environment variable first
        oob = os.environ.get('ODIN_OOB')
        if oob:
            return oob
        
        # Default OOB server (commonly used for testing)
        # You can change this to your own OOB server
        return 'interactsh.com'
    
    @classmethod
    def warmup(cls):
        """
        Warmup method called once before running checks against targets.
        
        This method can be overridden by subclasses to perform expensive
        initialization that should be done once, not per target.
        """
        pass
    
    @classmethod
    def set_data(cls, key: str, value: Any):
        """
        Store data that will be available to all check instances.
        
        This is useful for storing data retrieved during warmup() that
        should be available to all check executions.
        
        Args:
            key: Key to store the data under
            value: Value to store
        """
        cls._warmup_data[key] = value
    
    @classmethod
    def get_data(cls, key: str, default: Any = None) -> Any:
        """
        Retrieve data stored with set_data().
        
        Args:
            key: Key to retrieve
            default: Default value if key is not found
        
        Returns:
            Stored value or default
        """
        return cls._warmup_data.get(key, default)
    
    @classmethod
    def clear_data(cls):
        """Clear all stored warmup data."""
        cls._warmup_data.clear()
    
    @classmethod
    def get_metadata(cls) -> dict:
        """
        Get check metadata (name, severity, description, poc).
        
        Returns:
            Dictionary containing check metadata
        """
        return {
            'name': cls.name,
            'severity': cls.severity,
            'description': cls.description,
            'poc': cls.poc
        }
    
    def create_result(self, url: str = None, 
                      name: str = None, severity: str = None,
                      description: str = None, poc: str = None, **kwargs) -> CheckResult:
        """
        Create a CheckResult with check metadata pre-populated.
        
        Metadata from the check class will be used if not explicitly provided.
        
        Args:
            url: URL where the vulnerability was found
            name: Override check name
            severity: Override severity
            description: Override description
            poc: Override POC URL
            **kwargs: Additional attributes for CheckResult
        
        Returns:
            CheckResult instance with metadata populated
        """
        # Use provided values or fall back to class metadata
        result_name = name or self.name
        result_severity = severity or self.severity
        result_description = description or self.description
        result_poc = poc or self.poc
        
        return CheckResult(
            url=url,
            name=result_name,
            severity=result_severity,
            description=result_description,
            poc=result_poc,
            **kwargs
        )

