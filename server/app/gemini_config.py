import os
import json
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

# Load environment variables from the authoritative project-root .env file.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROOT_ENV_FILE = PROJECT_ROOT / ".env"
if ROOT_ENV_FILE.exists():
    load_dotenv(dotenv_path=str(ROOT_ENV_FILE), override=True)
else:
    logger.warning("Root .env not found at %s", ROOT_ENV_FILE)

class GeminiConfig:
    """Manage Gemini API configuration with advanced features"""
    
    # Default configuration
    DEFAULT_CONFIG = {
        'api_key': None,
        'api_keys': [],
        'model': 'gemini-1.5-pro',
        'temperature': 0.7,
        'max_tokens': 1000,
        'timeout': 30,
        'enabled': True,
        'max_retries': 3,
        'retry_delay': 2,
        'cache_enabled': True,
        'cache_ttl': 300,  # 5 minutes
        'log_level': 'INFO',
        'rate_limit': 60,  # requests per minute
        'batch_size': 10,
        'parallel_requests': 2,
        'safety_threshold': 'BLOCK_MEDIUM_AND_ABOVE'
    }
    
    # Available Gemini models
    AVAILABLE_MODELS = [
        'gemini-1.5-pro',
        'gemini-1.5-pro-latest',
        'gemini-pro',
        'gemini-1.0-pro',
        'gemini-1.0-pro-latest',
        'gemini-1.0-pro-vision'
    ]
    
    # Safety categories
    SAFETY_CATEGORIES = [
        'HARM_CATEGORY_HARASSMENT',
        'HARM_CATEGORY_HATE_SPEECH',
        'HARM_CATEGORY_SEXUALLY_EXPLICIT',
        'HARM_CATEGORY_DANGEROUS_CONTENT'
    ]
    
    # Safety thresholds
    SAFETY_THRESHOLDS = [
        'BLOCK_NONE',
        'BLOCK_ONLY_HIGH',
        'BLOCK_MEDIUM_AND_ABOVE',
        'BLOCK_LOW_AND_ABOVE'
    ]
    
    def __init__(self, config_file: str = None):
        """
        Initialize Gemini configuration
        
        Args:
            config_file: Path to JSON configuration file (optional)
        """
        self.config_file = config_file
        self.config_history = []
        self.validation_errors = []
        self.config = self.load_configuration()
        
    def load_configuration(self) -> Dict[str, Any]:
        """Load configuration from multiple sources"""
        config = self.DEFAULT_CONFIG.copy()
        
        # 1. Load from environment variables (highest priority)
        env_config = self._load_from_env()
        config.update(env_config)
        
        # 2. Load from JSON config file if provided
        if self.config_file and os.path.exists(self.config_file):
            file_config = self._load_from_file(self.config_file)
            config.update(file_config)
        
        # 3. Load from .env file (already loaded via load_dotenv)
        # Additional .env specific parsing if needed
        
        # 4. Validate and normalize
        config = self._normalize_config(config)
        
        # Store in history
        self.config_history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'config': config.copy()
        })
        
        # Short, one-line config summary
        masked = self._mask_sensitive_data(config)
        logger.info(f"Gemini: loaded {masked.get('model','?')} | temp={masked.get('temperature','?')} | enabled={masked.get('enabled','?')}")
        return config
    
    def _load_from_env(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}

        csv_keys: List[str] = []
        for csv_env in ('GEMINI_API_KEYS', 'GOOGLE_API_KEYS'):
            raw = os.getenv(csv_env, '')
            if raw:
                csv_keys.extend([item.strip() for item in raw.split(',') if item.strip()])
        for idx in range(1, 21):
            for env_name in (f'GEMINI_API_KEY_{idx}', f'GOOGLE_API_KEY_{idx}'):
                value = os.getenv(env_name, '').strip()
                if value:
                    csv_keys.append(value)
        
        # Map environment variables to config keys
        env_mapping = {
            'GEMINI_API_KEY': 'api_key',
            'GEMINI_MODEL': 'model',
            'GEMINI_TEMPERATURE': 'temperature',
            'GEMINI_MAX_TOKENS': 'max_tokens',
            'GEMINI_TIMEOUT': 'timeout',
            'GEMINI_ENABLED': 'enabled',
            'GEMINI_MAX_RETRIES': 'max_retries',
            'GEMINI_RETRY_DELAY': 'retry_delay',
            'GEMINI_CACHE_ENABLED': 'cache_enabled',
            'GEMINI_CACHE_TTL': 'cache_ttl',
            'GEMINI_LOG_LEVEL': 'log_level',
            'GEMINI_RATE_LIMIT': 'rate_limit',
            'GEMINI_BATCH_SIZE': 'batch_size',
            'GEMINI_PARALLEL_REQUESTS': 'parallel_requests',
            'GEMINI_SAFETY_THRESHOLD': 'safety_threshold'
        }
        
        for env_var, config_key in env_mapping.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Convert string values to appropriate types
                if config_key in ['temperature', 'retry_delay']:
                    env_config[config_key] = float(env_value)
                elif config_key in ['max_tokens', 'timeout', 'max_retries', 'cache_ttl', 
                                   'rate_limit', 'batch_size', 'parallel_requests']:
                    try:
                        env_config[config_key] = int(env_value)
                    except ValueError:
                        logger.warning(f"Invalid integer value for {env_var}: {env_value}")
                elif config_key == 'enabled':
                    env_config[config_key] = env_value.lower() in ['true', '1', 'yes', 'on']
                else:
                    env_config[config_key] = env_value

        if csv_keys:
            deduped = []
            seen = set()
            for key in csv_keys:
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(key)
            env_config['api_keys'] = deduped
        
        return env_config
    
    def _load_from_file(self, filepath: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(filepath, 'r') as f:
                file_config = json.load(f)
            logger.info(f"Loaded configuration from {filepath}")
            return file_config
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load config file {filepath}: {e}")
            return {}
    
    def _normalize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and validate configuration values"""
        normalized = config.copy()
        
        # Ensure temperature is within bounds
        if 'temperature' in normalized:
            normalized['temperature'] = max(0.0, min(1.0, normalized['temperature']))
        
        # Ensure model is valid
        if 'model' in normalized and normalized['model'] not in self.AVAILABLE_MODELS:
            logger.warning(f"Model {normalized['model']} not in available models. Using default.")
            normalized['model'] = self.DEFAULT_CONFIG['model']
        
        # Ensure safety threshold is valid
        if 'safety_threshold' in normalized and normalized['safety_threshold'] not in self.SAFETY_THRESHOLDS:
            logger.warning(f"Invalid safety threshold. Using default.")
            normalized['safety_threshold'] = self.DEFAULT_CONFIG['safety_threshold']
        
        # Ensure positive values
        for key in ['max_tokens', 'timeout', 'max_retries', 'cache_ttl', 
                   'rate_limit', 'batch_size', 'parallel_requests']:
            if key in normalized and normalized[key] <= 0:
                normalized[key] = self.DEFAULT_CONFIG[key]
                logger.warning(f"Invalid {key} value. Using default: {normalized[key]}")
        
        return normalized
    
    def validate(self) -> Dict[str, Any]:
        """
        Validate configuration and return validation results
        
        Returns:
            Dictionary with validation results and any errors
        """
        self.validation_errors = []
        
        # Check required fields
        if self.config['enabled']:
            api_key = str(self.config.get('api_key') or '').strip()
            api_keys = self.config.get('api_keys') or []
            if not api_key and not api_keys:
                self.validation_errors.append("At least one Gemini key is required when Gemini is enabled (GEMINI_API_KEY or GEMINI_API_KEYS/GEMINI_API_KEY_1..N)")
            
            # Validate API key format (basic check)
            if api_key and len(api_key) < 20:
                self.validation_errors.append("API key appears to be invalid (too short)")
            for key in api_keys:
                if len(str(key or '').strip()) < 20:
                    self.validation_errors.append("One of GEMINI_API_KEYS entries appears invalid (too short)")
        
        # Validate model
        if self.config['model'] not in self.AVAILABLE_MODELS:
            self.validation_errors.append(f"Model {self.config['model']} is not a valid Gemini model")
        
        # Validate numeric ranges
        if not (0.0 <= self.config['temperature'] <= 1.0):
            self.validation_errors.append(f"Temperature must be between 0.0 and 1.0, got {self.config['temperature']}")
        
        if self.config['max_tokens'] > 8192:
            self.validation_errors.append(f"Max tokens cannot exceed 8192, got {self.config['max_tokens']}")
        
        # Validate safety settings
        if self.config['safety_threshold'] not in self.SAFETY_THRESHOLDS:
            self.validation_errors.append(f"Invalid safety threshold: {self.config['safety_threshold']}")
        
        validation_result = {
            'valid': len(self.validation_errors) == 0,
            'errors': self.validation_errors.copy(),
            'warnings': [],
            'config_hash': self.get_config_hash(),
            'timestamp': utcnow().isoformat()
        }
        
        if not validation_result['valid']:
            logger.error(f"Configuration validation failed: {self.validation_errors}")
        else:
            logger.info("Gemini: config valid")
        
        return validation_result
    
    def get_config(self, key: str = None, default: Any = None) -> Any:
        """
        Get configuration value or entire config
        
        Args:
            key: Configuration key to retrieve (optional)
            default: Default value if key not found
            
        Returns:
            Configuration value or entire config dictionary
        """
        if key is None:
            return self.config.copy()
        
        return self.config.get(key, default)
    
    def update_config(self, updates: Dict[str, Any], save_to_file: bool = False) -> bool:
        """
        Update configuration
        
        Args:
            updates: Dictionary of configuration updates
            save_to_file: Whether to save to config file
            
        Returns:
            True if update successful, False otherwise
        """
        # Create backup of current config
        backup = self.config.copy()
        
        try:
            # Apply updates
            self.config.update(updates)
            
            # Normalize updated config
            self.config = self._normalize_config(self.config)
            
            # Validate
            validation = self.validate()
            if not validation['valid']:
                logger.error(f"Update validation failed: {validation['errors']}")
                self.config = backup  # Revert to backup
                return False
            
            # Add to history
            self.config_history.append({
                'timestamp': utcnow().isoformat(),
                'config': self.config.copy(),
                'updates': updates
            })
            
            # Keep only last 10 history entries
            if len(self.config_history) > 10:
                self.config_history = self.config_history[-10:]
            
            # Save to file if requested
            if save_to_file and self.config_file:
                self.save_to_file(self.config_file)
            
            logger.info(f"Configuration updated: {self._mask_sensitive_data(updates)}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            self.config = backup  # Revert to backup
            return False
    
    def save_to_file(self, filepath: str = None) -> bool:
        """
        Save configuration to JSON file
        
        Args:
            filepath: Path to save file (uses instance path if None)
            
        Returns:
            True if save successful, False otherwise
        """
        save_path = filepath or self.config_file
        if not save_path:
            logger.error("No filepath specified for saving configuration")
            return False
        
        try:
            # Ensure directory exists
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Create save data with metadata
            save_data = {
                'config': self.config,
                'metadata': {
                    'version': '1.0.0',
                    'last_updated': utcnow().isoformat(),
                    'config_hash': self.get_config_hash()
                }
            }
            
            with open(save_path, 'w') as f:
                json.dump(save_data, f, indent=2, default=str)
            
            logger.info(f"Configuration saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration to {save_path}: {e}")
            return False
    
    def get_config_hash(self) -> str:
        """
        Get hash of current configuration (excluding sensitive data)
        
        Returns:
            MD5 hash string
        """
        # Create copy without sensitive data
        safe_config = self.config.copy()
        if 'api_key' in safe_config:
            safe_config['api_key'] = '***MASKED***'
        
        config_str = json.dumps(safe_config, sort_keys=True)
        return hashlib.md5(config_str.encode()).hexdigest()
    
    def _mask_sensitive_data(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive data for logging"""
        masked = config.copy()
        if 'api_key' in masked and masked['api_key']:
            masked['api_key'] = f"{masked['api_key'][:8]}...{masked['api_key'][-4:]}"
        return masked
    
    def get_safety_settings(self) -> List[Dict[str, str]]:
        """
        Get safety settings for Gemini API
        
        Returns:
            List of safety setting dictionaries
        """
        threshold = self.config.get('safety_threshold', 'BLOCK_MEDIUM_AND_ABOVE')
        
        safety_settings = []
        for category in self.SAFETY_CATEGORIES:
            safety_settings.append({
                "category": category,
                "threshold": threshold
            })
        
        return safety_settings
    
    def get_generation_config(self) -> Dict[str, Any]:
        """
        Get generation configuration for Gemini API
        
        Returns:
            Generation configuration dictionary
        """
        return {
            "temperature": self.config['temperature'],
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": self.config['max_tokens'],
            "response_mime_type": "text/plain"
        }
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """
        Get configuration usage statistics
        
        Returns:
            Dictionary with usage statistics
        """
        return {
            'config_changes': len(self.config_history),
            'last_change': self.config_history[-1]['timestamp'] if self.config_history else None,
            'current_hash': self.get_config_hash(),
            'validation_errors': len(self.validation_errors),
            'config_age': self._get_config_age()
        }
    
    def _get_config_age(self) -> Optional[int]:
        """Get age of current config in seconds"""
        if not self.config_history:
            return None
        
        last_change = datetime.fromisoformat(self.config_history[-1]['timestamp'].replace('Z', '+00:00'))
        return int((utcnow() - last_change).total_seconds())
    
    def print_config(self, show_sensitive: bool = False):
        """Print current configuration"""
        print("\n" + "="*60)
        print("GEMINI CONFIGURATION")
        print("="*60)
        
        # Get config to display
        display_config = self.config.copy()
        if not show_sensitive and 'api_key' in display_config:
            display_config['api_key'] = '***MASKED***'
        
        # Print basic configuration
        print("\nBasic Configuration:")
        print("-" * 40)
        for key in ['enabled', 'model', 'temperature', 'max_tokens', 'timeout']:
            if key in display_config:
                print(f"  {key:20}: {display_config[key]}")
        
        # Print API configuration
        print("\nAPI Configuration:")
        print("-" * 40)
        for key in ['api_key', 'max_retries', 'retry_delay', 'rate_limit']:
            if key in display_config:
                print(f"  {key:20}: {display_config[key]}")
        
        # Print advanced configuration
        print("\nAdvanced Configuration:")
        print("-" * 40)
        for key in ['cache_enabled', 'cache_ttl', 'batch_size', 
                   'parallel_requests', 'safety_threshold', 'log_level']:
            if key in display_config:
                print(f"  {key:20}: {display_config[key]}")
        
        # Print validation status
        validation = self.validate()
        print("\nValidation Status:")
        print("-" * 40)
        print(f"  Status: {'✅ Valid' if validation['valid'] else '❌ Invalid'}")
        print(f"  Config Hash: {validation['config_hash']}")
        
        if validation['errors']:
            print(f"  Errors: {len(validation['errors'])}")
            for error in validation['errors']:
                print(f"    - {error}")
        
        # Print usage stats
        stats = self.get_usage_stats()
        print("\nUsage Statistics:")
        print("-" * 40)
        print(f"  Config Changes: {stats['config_changes']}")
        print(f"  Last Change: {stats['last_change']}")
        if stats['config_age']:
            print(f"  Config Age: {stats['config_age']} seconds")
        
        print("="*60 + "\n")
    
    def export_config(self, format: str = 'json') -> str:
        """
        Export configuration in specified format
        
        Args:
            format: Export format ('json', 'yaml', 'env')
            
        Returns:
            Configuration string in specified format
        """
        config_copy = self.config.copy()
        
        if format.lower() == 'json':
            return json.dumps(config_copy, indent=2, default=str)
        
        elif format.lower() == 'env':
            env_lines = []
            for key, value in config_copy.items():
                if value is not None:
                    env_key = f"GEMINI_{key.upper()}"
                    env_lines.append(f"{env_key}={value}")
            return "\n".join(env_lines)
        
        elif format.lower() == 'yaml':
            try:
                import yaml
                return yaml.dump(config_copy, default_flow_style=False)
            except ImportError:
                logger.error("PyYAML not installed for YAML export")
                return ""
        
        else:
            logger.error(f"Unsupported export format: {format}")
            return ""
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        return self.update_config(self.DEFAULT_CONFIG)


# Factory function for creating config instance
_config_instance = None

def get_gemini_config(config_file: str = None) -> GeminiConfig:
    """
    Get or create Gemini configuration instance
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        GeminiConfig instance
    """
    global _config_instance
    
    if _config_instance is None:
        # Try to find config file if not specified
        if config_file is None:
            # Check common locations
            possible_paths = [
                os.path.join(os.getcwd(), 'config', 'gemini_config.json'),
                os.path.join(os.getcwd(), 'gemini_config.json'),
                os.path.join(os.path.dirname(__file__), 'gemini_config.json'),
                os.path.expanduser('~/.sentinelai/gemini_config.json')
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    config_file = path
                    logger.info(f"Found config file: {config_file}")
                    break
        
        _config_instance = GeminiConfig(config_file)
    
    return _config_instance


# Utility functions for common operations
def validate_gemini_config() -> bool:
    """Quick validation of Gemini configuration"""
    config = get_gemini_config()
    return config.validate()['valid']

def get_gemini_api_key() -> Optional[str]:
    """Get Gemini API key safely"""
    config = get_gemini_config()
    return config.get_config('api_key')

def is_gemini_enabled() -> bool:
    """Check if Gemini is enabled"""
    config = get_gemini_config()
    return config.get_config('enabled', False)

def get_gemini_model() -> str:
    """Get configured Gemini model"""
    config = get_gemini_config()
    return config.get_config('model', 'gemini-1.5-pro')


# Example usage and testing
if __name__ == "__main__":
    print("Testing Gemini Configuration Module")
    print("-" * 50)
    
    # Create config instance
    config = get_gemini_config()
    
    # Print configuration
    config.print_config()
    
    # Test validation
    validation_result = config.validate()
    print(f"Validation Result: {'PASS' if validation_result['valid'] else 'FAIL'}")
    
    # Export configuration
    print("\nExported ENV format:")
    print(config.export_config('env'))
    
    # Get usage stats
    stats = config.get_usage_stats()
    print(f"\nConfig has been changed {stats['config_changes']} times")
 
    # Test safety settings
    safety_settings = config.get_safety_settings()
    print(f"\nSafety Settings ({len(safety_settings)} categories):")
    for setting in safety_settings:
        print(f"  {setting['category']}: {setting['threshold']}")
    
    # Test generation config
    gen_config = config.get_generation_config()
    print(f"\nGeneration Configuration:")
    for key, value in gen_config.items():
        print(f"  {key}: {value}")
    
    # Test config update
    print("\n" + "="*50)
    print("Testing configuration updates...")
    
    test_updates = {
        'temperature': 0.5,
        'max_tokens': 2000
    }
    
    success = config.update_config(test_updates)
    print(f"Update successful: {success}")
    
    if success:
        print(f"New temperature: {config.get_config('temperature')}")
        print(f"New max tokens: {config.get_config('max_tokens')}")
    
    # Test invalid update
    invalid_updates = {
        'temperature': 2.5,  # Invalid: should be 0-1
        'max_tokens': -100   # Invalid: should be positive
    }
    
    success = config.update_config(invalid_updates)
    print(f"Invalid update successful (should be False): {success}")
    
    # Show final configuration
    print("\n" + "="*50)
    print("Final Configuration:")
    config.print_config()
    
    # Test export formats
    print("\n" + "="*50)
    print("Export Tests:")
    
    json_export = config.export_config('json')
    print(f"JSON Export Length: {len(json_export)} characters")
    
    env_export = config.export_config('env')
    print(f"ENV Export Length: {len(env_export)} characters")
    print(f"\nFirst few lines of ENV export:")
    for line in env_export.split('\n')[:5]:
        print(f"  {line}")
    
    # Test utility functions
    print("\n" + "="*50)
    print("Utility Function Tests:")
    
    print(f"Validate config: {validate_gemini_config()}")
    print(f"API key available: {'Yes' if get_gemini_api_key() else 'No'}")
    print(f"Gemini enabled: {is_gemini_enabled()}")
    print(f"Gemini model: {get_gemini_model()}")
    
    # Test config reset
    print("\n" + "="*50)
    print("Testing configuration reset...")
    
    success = config.reset_to_defaults()
    print(f"Reset to defaults successful: {success}")
    
    if success:
        print(f"Temperature after reset: {config.get_config('temperature')}")
        print(f"Model after reset: {config.get_config('model')}")
    
    # Test file operations
    print("\n" + "="*50)
    print("Testing file operations...")
    
    # Save to temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        tmp_path = tmp.name
    
    success = config.save_to_file(tmp_path)
    print(f"Save to file successful: {success}")
    
    if success and os.path.exists(tmp_path):
        print(f"File created: {tmp_path}")
        print(f"File size: {os.path.getsize(tmp_path)} bytes")
        
        # Load from saved file
        new_config = GeminiConfig(tmp_path)
        print(f"Loaded from file - Model: {new_config.get_config('model')}")
        
        # Clean up
        os.unlink(tmp_path)
        print(f"Temporary file cleaned up")
    
    # Test monitoring capabilities
    print("\n" + "="*50)
    print("Monitoring and History:")
    
    print(f"Config history entries: {len(config.config_history)}")
    if config.config_history:
        print(f"Most recent change: {config.config_history[-1]['timestamp']}")
        
        # Show history summary
        print(f"\nConfiguration History (last {min(3, len(config.config_history))} entries):")
        for i, entry in enumerate(config.config_history[-3:]):
            idx = len(config.config_history) - 3 + i
            print(f"  [{idx}] {entry['timestamp']}: {len(entry.get('config', {}))} parameters")
    
    # Test error handling
    print("\n" + "="*50)
    print("Error Handling Tests:")
    
    # Test with non-existent config file
    non_existent_config = GeminiConfig("/non/existent/path/config.json")
    print(f"Config loaded with non-existent file: {non_existent_config.get_config('model')}")
    
    # Test validation with missing API key
    test_config = GeminiConfig()
    test_config.update_config({'api_key': ''})
    validation = test_config.validate()
    print(f"Validation without API key (when enabled): {'Has errors' if not validation['valid'] else 'No errors'}")
    
    # Performance test
    print("\n" + "="*50)
    print("Performance Tests:")
    
    import time
    start_time = time.time()
    
    # Multiple config operations
    for i in range(100):
        config.get_config('model')
        config.get_config('temperature')
    
    end_time = time.time()
    print(f"100 config get operations: {(end_time - start_time) * 1000:.2f} ms")
    
    # Hash performance
    start_time = time.time()
    for i in range(1000):
        config.get_config_hash()
    end_time = time.time()
    print(f"1000 hash calculations: {(end_time - start_time) * 1000:.2f} ms")
    
    print("\n" + "="*50)
    print("Configuration Module Test Complete!")
    print("="*50)


# Additional utility functions for common integrations
def configure_gemini_for_environment(environment: str = 'production') -> GeminiConfig:
    """
    Configure Gemini for specific environment
    
    Args:
        environment: Environment name ('development', 'staging', 'production')
        
    Returns:
        Configured GeminiConfig instance
    """
    config = get_gemini_config()
    
    # Environment-specific defaults
    env_defaults = {
        'development': {
            'temperature': 0.9,
            'max_tokens': 500,
            'log_level': 'DEBUG',
            'safety_threshold': 'BLOCK_ONLY_HIGH'
        },
        'staging': {
            'temperature': 0.7,
            'max_tokens': 1000,
            'log_level': 'INFO',
            'safety_threshold': 'BLOCK_MEDIUM_AND_ABOVE'
        },
        'production': {
            'temperature': 0.3,
            'max_tokens': 1500,
            'log_level': 'WARNING',
            'safety_threshold': 'BLOCK_MEDIUM_AND_ABOVE',
            'max_retries': 5,
            'rate_limit': 30
        }
    }
    
    if environment in env_defaults:
        config.update_config(env_defaults[environment])
        logger.info(f"Configured Gemini for {environment} environment")
    
    return config


def create_minimal_config(api_key: str, model: str = None) -> GeminiConfig:
    """
    Create a minimal configuration with just API key and model
    
    Args:
        api_key: Gemini API key
        model: Gemini model name
        
    Returns:
        GeminiConfig instance
    """
    config = GeminiConfig()
    
    minimal_config = {
        'api_key': api_key,
        'model': model or 'gemini-1.5-pro',
        'enabled': True
    }
    
    config.update_config(minimal_config)
    return config


# Configuration presets for different use cases
class GeminiConfigPresets:
    """Predefined configuration presets for common use cases"""
    
    @staticmethod
    def creative_writing() -> Dict[str, Any]:
        """Preset for creative writing"""
        return {
            'temperature': 0.9,
            'max_tokens': 2000,
            'model': 'gemini-1.5-pro',
            'safety_threshold': 'BLOCK_ONLY_HIGH'
        }
    
    @staticmethod
    def code_generation() -> Dict[str, Any]:
        """Preset for code generation"""
        return {
            'temperature': 0.2,
            'max_tokens': 4000,
            'model': 'gemini-1.5-pro',
            'safety_threshold': 'BLOCK_MEDIUM_AND_ABOVE'
        }
    
    @staticmethod
    def data_analysis() -> Dict[str, Any]:
        """Preset for data analysis"""
        return {
            'temperature': 0.3,
            'max_tokens': 3000,
            'model': 'gemini-1.5-pro',
            'safety_threshold': 'BLOCK_MEDIUM_AND_ABOVE'
        }
    
    @staticmethod
    def conversation() -> Dict[str, Any]:
        """Preset for conversational AI"""
        return {
            'temperature': 0.7,
            'max_tokens': 1000,
            'model': 'gemini-1.5-pro',
            'safety_threshold': 'BLOCK_MEDIUM_AND_ABOVE'
        }
    
    @staticmethod
    def high_volume() -> Dict[str, Any]:
        """Preset for high-volume processing"""
        return {
            'temperature': 0.4,
            'max_tokens': 800,
            'model': 'gemini-1.5-pro',
            'rate_limit': 100,
            'batch_size': 20,
            'parallel_requests': 4,
            'cache_enabled': True,
            'cache_ttl': 600
        }


# Health check function for monitoring
def check_gemini_config_health() -> Dict[str, Any]:
    """
    Perform comprehensive health check on Gemini configuration
    
    Returns:
        Dictionary with health check results
    """
    config = get_gemini_config()
    
    health_results = {
        'timestamp': utcnow().isoformat(),
        'status': 'healthy',
        'checks': {},
        'issues': []
    }
    
    # Check 1: Configuration validation
    validation = config.validate()
    health_results['checks']['validation'] = {
        'passed': validation['valid'],
        'errors': validation['errors']
    }
    
    if not validation['valid']:
        health_results['status'] = 'unhealthy'
        health_results['issues'].append('Configuration validation failed')
    
    # Check 2: API key availability
    api_key = config.get_config('api_key')
    health_results['checks']['api_key'] = {
        'present': bool(api_key),
        'length': len(api_key) if api_key else 0
    }
    
    if config.get_config('enabled') and not api_key:
        health_results['status'] = 'unhealthy'
        health_results['issues'].append('API key missing but Gemini is enabled')
    
    # Check 3: Configuration age
    config_age = config._get_config_age()
    health_results['checks']['config_age'] = {
        'seconds': config_age,
        'hours': config_age / 3600 if config_age else 0
    }
    
    if config_age and config_age > 86400:  # Older than 24 hours
        health_results['issues'].append('Configuration is older than 24 hours')
    
    # Check 4: Rate limit configuration
    rate_limit = config.get_config('rate_limit')
    health_results['checks']['rate_limit'] = {
        'value': rate_limit,
        'within_bounds': 1 <= rate_limit <= 1000
    }
    
    if not (1 <= rate_limit <= 1000):
        health_results['issues'].append('Rate limit is outside recommended bounds')
    
    # Check 5: Cache configuration
    cache_enabled = config.get_config('cache_enabled')
    cache_ttl = config.get_config('cache_ttl')
    health_results['checks']['cache'] = {
        'enabled': cache_enabled,
        'ttl_seconds': cache_ttl
    }
    
    if cache_enabled and cache_ttl > 3600:
        health_results['issues'].append('Cache TTL is very long (over 1 hour)')
    
    # Overall health score
    passed_checks = sum(1 for check in health_results['checks'].values() 
                       if check.get('passed', True))
    total_checks = len(health_results['checks'])
    
    health_results['health_score'] = f"{passed_checks}/{total_checks}"
    health_results['summary'] = f"Configuration is {health_results['status'].upper()}"
    
    return health_results


# Configuration migration helper
def migrate_config_v1_to_v2(old_config_path: str, new_config_path: str) -> bool:
    """
    Migrate configuration from v1 to v2 format
    
    Args:
        old_config_path: Path to old configuration file
        new_config_path: Path to save new configuration
        
    Returns:
        True if migration successful
    """
    try:
        # Load old config
        with open(old_config_path, 'r') as f:
            old_config = json.load(f)
        
        # Migration mapping
        migration_map = {
            'gemini_api_key': 'api_key',
            'gemini_model': 'model',
            'gemini_temp': 'temperature',
            'max_output_tokens': 'max_tokens',
            'request_timeout': 'timeout'
        }
        
        # Migrate values
        new_config = {}
        for old_key, new_key in migration_map.items():
            if old_key in old_config:
                new_config[new_key] = old_config[old_key]
        
        # Add new fields with defaults
        new_config.update({
            'enabled': old_config.get('enabled', True),
            'max_retries': 3,
            'cache_enabled': True,
            'log_level': 'INFO'
        })
        
        # Save new config
        config = GeminiConfig()
        config.update_config(new_config)
        
        return config.save_to_file(new_config_path)
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return False


# Decorator for configuration-aware functions
def with_gemini_config(func):
    """
    Decorator to inject Gemini configuration into function
    
    Usage:
        @with_gemini_config
        def my_function(gemini_config, other_args):
            # Use gemini_config here
    """
    def wrapper(*args, **kwargs):
        config = get_gemini_config()
        return func(config, *args, **kwargs)
    return wrapper


# Singleton instance for global access
GEMINI_CONFIG = get_gemini_config()
