#!/usr/bin/env python3
"""
Check Loader - Discovers and loads all check modules dynamically
"""
import os
import sys
import importlib.util
from pathlib import Path
from typing import List, Type, Optional
from odin.odin_check import OdinCheck


# Base directory for checks
CHECKS_DIR = Path(__file__).parent / 'checks'


def discover_check_files() -> List[Path]:
    """
    Discover all check files in the checks directory.
    
    Returns:
        List of Path objects pointing to check files
    """
    check_files = []
    
    if not CHECKS_DIR.exists():
        return check_files
    
    # Walk through all subdirectories
    for root, dirs, files in os.walk(CHECKS_DIR):
        # Skip __pycache__ directories
        dirs[:] = [d for d in dirs if d != '__pycache__']
        
        for file in files:
            # Only process Python files
            if not file.endswith('.py'):
                continue
            
            # Skip odin_check.py (it's a base class, not a check)
            if file == 'odin_check.py':
                continue
            
            file_path = Path(root) / file
            check_files.append(file_path)
    
    return sorted(check_files)


def load_check_class(file_path: Path) -> Optional[Type[OdinCheck]]:
    """
    Load a Check class from a Python file.
    
    Args:
        file_path: Path to the check file
    
    Returns:
        Check class if found, None otherwise
    """
    try:
        # Convert to absolute path
        file_path = file_path.resolve()
        
        # Ensure the parent directory (where odin is) is in sys.path
        # This allows checks to import from odin
        parent_dir = str(file_path.parent.parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        
        # Generate a unique module name based on file path
        # Replace path separators and dots with underscores
        module_name = f"check_{file_path.stem}_{abs(hash(str(file_path)))}"
        
        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            return None
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Look for Check class
        if hasattr(module, 'Check'):
            check_class = getattr(module, 'Check')
            # Verify it's a subclass of OdinCheck
            if issubclass(check_class, OdinCheck):
                return check_class
        
        return None
    
    except Exception as e:
        # Silently fail - we'll log errors in the runner
        return None


def load_all_checks() -> List[Type[OdinCheck]]:
    """
    Discover and load all checks from the checks directory.
    
    Returns:
        List of Check classes
    """
    check_files = discover_check_files()
    check_classes = []
    
    for file_path in check_files:
        check_class = load_check_class(file_path)
        if check_class:
            check_classes.append(check_class)
    
    return check_classes


def warmup_checks(check_classes: List[Type[OdinCheck]]):
    """
    Call warmup() on all check classes that have it.
    
    Args:
        check_classes: List of Check classes
    """
    for check_class in check_classes:
        try:
            if hasattr(check_class, 'warmup'):
                check_class.warmup()
        except Exception:
            # Silently continue if warmup fails
            pass

