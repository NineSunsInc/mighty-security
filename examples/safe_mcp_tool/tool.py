
import json
import sys


def process_mcp_request(request_data):
    '''Process MCP request safely'''
    try:
        # Parse JSON input
        data = json.loads(request_data)

        # Validate input
        if 'method' not in data:
            return {"error": "Missing method"}

        # Process based on method
        if data['method'] == 'echo':
            return {"result": data.get('params', {})}

        return {"error": "Unknown method"}

    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    request = sys.stdin.read()
    response = process_mcp_request(request)
    print(json.dumps(response))
