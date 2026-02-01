```python
import json
import sys

def parse_eve(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    print(json.dumps(data, indent=2))
            except:
                continue

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_eve.py eve.json")
    else:
        parse_eve(sys.argv[1])
