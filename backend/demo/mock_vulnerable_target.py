import http.server
import urllib.parse
import json

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)
        
        # Super simple simulated vulnerability
        # If the parameter 'id' contains typical boolean truth syntax, return 200 with different content.
        # If it contains false, return "not found".
        # If it has a sleep command, simulate latency.
        # If it has a syntax error (like unclosed quote), return a mock SQL error.

        response_body = "Home Page. No ID provided."
        status_code = 200

        if 'id' in query:
            param_val = query['id'][0].lower()
            
            if "sleep" in param_val or "waitfor" in param_val or "pg_sleep" in param_val:
                import time
                time.sleep(5)
                response_body = "User profile: 1 (Delayed)"
            elif "'" in param_val and ("--" not in param_val and "#" not in param_val and "/*" not in param_val):
                # Unclosed quote
                status_code = 500
                response_body = "Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '' at line 1"
            elif "and 1=2" in param_val or "and false" in param_val or "1=0" in param_val or "2=3" in param_val:
                response_body = "User not found."
            else:
                response_body = "User profile: 1 (Active User). Welcome ADMIN."
        
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_body.encode())

if __name__ == "__main__":
    server_address = ('', 8081)
    httpd = http.server.HTTPServer(server_address, VulnerableHandler)
    print("Serving vulnerable test app on port 8081...")
    httpd.serve_forever()
