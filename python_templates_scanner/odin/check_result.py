"""
CheckResult - Represents the result of a vulnerability check
"""


class CheckResult:
    """Represents a result from a vulnerability check."""
    
    def __init__(self, url: str = None, 
                 name: str = None, severity: str = None, 
                 description: str = None, poc: str = None, **kwargs):
        """
        Initialize a CheckResult.
        
        Args:
            url: URL where the vulnerability was found (optional)
            name: Name of the vulnerability/check (optional)
            severity: Severity level (Critical/High/Medium/Low/Info) (optional)
            description: Description of the vulnerability (optional)
            poc: URL to proof of concept or exploit (optional)
            **kwargs: Additional attributes to store in the result
        """
        self.url = url
        self.name = name
        self.severity = severity
        self.description = description
        self.poc = poc
        
        # Store any additional keyword arguments as attributes
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        """Convert the result to a dictionary."""
        result = {}
        if self.url:
            result['url'] = self.url
        if self.name:
            result['name'] = self.name
        if self.severity:
            result['severity'] = self.severity
        if self.description:
            result['description'] = self.description
        if self.poc:
            result['poc'] = self.poc
        
        # Include any additional attributes
        for key, value in self.__dict__.items():
            if key not in ['url', 'name', 'severity', 'description', 'poc']:
                result[key] = value
        
        return result
    
    def __repr__(self):
        attrs = []
        if self.url:
            attrs.append(f'url={self.url!r}')
        if self.name:
            attrs.append(f'name={self.name!r}')
        if self.severity:
            attrs.append(f'severity={self.severity!r}')
        if self.description:
            attrs.append(f'description={self.description!r}')
        if self.poc:
            attrs.append(f'poc={self.poc!r}')
        for key, value in self.__dict__.items():
            if key not in ['url', 'name', 'severity', 'description', 'poc']:
                attrs.append(f'{key}={value!r}')
        return f'CheckResult({", ".join(attrs)})'

