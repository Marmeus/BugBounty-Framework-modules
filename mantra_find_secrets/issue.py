class Issue:

    def __init__(self, target, name, severity, description, poc, scanner, program_id, discovered_at):
        self.target = target
        self.name = name
        self.severity = severity
        self.description = description
        self.poc = poc
        self.scanner = scanner
        self.program_id = program_id
        self.discovered_at = discovered_at

    def to_dict(self):
        return {
                'program_id': self.program_id,
                'target': self.target,
                'name': self.name,
                'severity': self.severity,
                'description': self.description,
                'poc': self.poc,
                'scanner': self.scanner,
                'discovered_at': self.discovered_at
            }
    
    def __str__(self):
        return (f"Name: {self.name}\n"
                f"  Program ID: {self.program_id}\n"
                f"  Target: {self.target}\n"
                f"  Severity: {self.severity}\n"
                f"  Description: {self.description}\n"
                f"  Proof of Concept: {self.poc}\n"
                f"  Scanner: {self.scanner}\n"
                f"  Discovered At: {self.discovered_at}\n")


        


