from pathlib import Path
import readline
import atexit 

class HistoryManager:
    def __init__(self, namespace: str = "global"):
        self.namespace = namespace
        self.histfile = Path.home() / ".config" / "nipm" / f".history_{namespace}"
        self.histfile.parent.mkdir(parents=True, exist_ok=True)
        self._setup_readline()
    
    def _setup_readline(self):
        try:
            readline.read_history_file(self.histfile)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)
        readline.set_completer(self.interface_completer)
        readline.parse_and_bind("tab: complete")
        atexit.register(readline.write_history_file, self.histfile)
        self.readline_available = True
    
    def input(self, prompt_text: str) -> str:
        return input(prompt_text).strip()

    def interface_completer(self, text, state):
        interfaces = [iface.name for iface in Path("/sys/class/net").iterdir() if iface.is_dir()]
        matches = [i for i in interfaces if i.startswith(text)]
        return matches[state] if state < len(matches) else None

def interfaces_completer(prefix, **kwargs):
    try:
        return [
            iface.name 
            for iface in Path("/sys/class/net").iterdir() 
            if iface.is_dir() and iface.name.startswith(prefix)
        ]
    except Exception:
        return []
