import os
from pathlib import Path

class PolicyFileCache:
    def __init__(self, cache_dir="/tmp/policy_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
    def store_policy(self, attack_type, translated_xml):
        """
        Saves the translated policy (XML) to a file
        """
        filename = f"policy_{attack_type}.xml"
        filepath = self.cache_dir / filename
        
        try:
            with open(filepath, 'w') as f:
                f.write(translated_xml)
            print(f"Policy saved in: {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error saving policy: {e}")
            return False
    
    def get_and_clear_policy(self, attack_type):
        """
        Reads the translated policy and deletes the file
        """
        filename = f"policy_{attack_type}.xml"
        filepath = self.cache_dir / filename
        
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    translated_xml = f.read()
                os.remove(filepath)
                print(f"Read policy and removed file: {filepath}")
                return translated_xml
            except Exception as e:
                print(f"❌ Error reading policy: {e}")
                return None
        return None