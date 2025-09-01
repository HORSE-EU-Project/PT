import os
from pathlib import Path

class PolicyFileCache:
    def __init__(self, cache_dir="/tmp/policy_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
    def store_policy(self, attack_type, translated_xml):
        """
        Guarda la política traducida (XML) en un archivo
        """
        filename = f"policy_{attack_type}.xml"
        filepath = self.cache_dir / filename
        
        try:
            with open(filepath, 'w') as f:
                f.write(translated_xml)
            print(f"💾 Política guardada en: {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error guardando política: {e}")
            return False
    
    def get_and_clear_policy(self, attack_type):
        """
        Lee la política traducida y elimina el archivo
        """
        filename = f"policy_{attack_type}.xml"
        filepath = self.cache_dir / filename
        
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    translated_xml = f.read()
                os.remove(filepath)
                print(f"📖 Política leída y archivo eliminado: {filepath}")
                return translated_xml
            except Exception as e:
                print(f"❌ Error leyendo política: {e}")
        
        return None