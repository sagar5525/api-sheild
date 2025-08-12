import sys
import os
import json
import argparse
import re
import webbrowser
from urllib.parse import urlparse

def parse_postman_collection(file_path):
    """Parse Postman collection and extract endpoints with detailed parameters"""
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        raise FileNotFoundError(f"Postman file not found: {file_path}")
    
    endpoints = []
    
    def extract_endpoints(items, folder_path=""):
        for item in items:
            if 'item' in item:  # This is a folder
                folder_name = folder_path + "/" + item['name'] if folder_path else item['name']
                extract_endpoints(item['item'], folder_name)
            elif 'request' in item:  # This is a request
                request = item['request']
                method = request.get('method', 'GET')
                url = request.get('url', {})
                
                # Handle different URL formats
                if isinstance(url, dict):
                    raw_url = url.get('raw', '')
                else:
                    raw_url = str(url)
                
                # Extract path parameters from URL template
                path_params = []
                if isinstance(url, dict) and 'variable' in url:
                    for var in url['variable']:
                        path_params.append(var['key'])
                
                # Extract query parameters
                query_params = []
                if isinstance(url, dict) and 'query' in url:
                    for param in url['query']:
                        query_params.append(param['key'])
                
                # Extract headers
                headers = []
                if 'header' in request:
                    for header in request['header']:
                        if isinstance(header, dict):
                            headers.append(header.get('key', ''))
                
                # Extract body parameters
                body_params = []
                body_type = None
                if 'body' in request:
                    body = request['body']
                    body_type = body.get('mode')
                    
                    if body_type == 'raw':
                        raw_body = body.get('raw', '')
                        # Try to parse JSON body
                        try:
                            if body.get('options', {}).get('raw', {}).get('language') == 'json':
                                json_body = json.loads(raw_body)
                                body_params = extract_json_keys(json_body)
                            elif raw_body.strip().startswith('{') or raw_body.strip().startswith('['):
                                json_body = json.loads(raw_body)
                                body_params = extract_json_keys(json_body)
                            else:
                                body_params = ['raw_text_body']
                        except:
                            body_params = ['raw_body']
                    elif body_type == 'formdata':
                        form_data = body.get('formdata', [])
                        for param in form_data:
                            if isinstance(param, dict):
                                body_params.append(param.get('key', ''))
                    elif body_type == 'urlencoded':
                        urlencoded = body.get('urlencoded', [])
                        for param in urlencoded:
                            if isinstance(param, dict):
                                body_params.append(param.get('key', ''))
                    elif body_type == 'file':
                        body_params = ['file_upload']
                
                # Extract authentication
                auth = 'None'
                if 'auth' in request:
                    auth = request['auth'].get('type', 'Unknown')
                elif 'auth' in data:  # Check collection-level auth
                    auth = data['auth'].get('type', 'Unknown')
                
                endpoint_data = {
                    'method': method,
                    'path': raw_url,
                    'description': item.get('name', 'No description'),
                    'auth': auth,
                    'path_params': path_params,
                    'query_params': query_params,
                    'headers': headers,
                    'body_params': body_params,
                    'body_type': body_type
                }
                
                endpoints.append(endpoint_data)
    
    def extract_json_keys(obj, prefix=''):
        """Recursively extract keys from JSON object"""
        keys = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                keys.append(key)
                if isinstance(value, (dict, list)):
                    keys.extend(extract_json_keys(value, key))
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    keys.extend(extract_json_keys(item, prefix))
        return keys
    
    extract_endpoints(data.get('item', []))
    return endpoints

def extract_schema_properties(schema):
    """Extract properties from JSON schema - GLOBAL FUNCTION"""
    properties = []
    if isinstance(schema, dict):
        props = schema.get('properties', {})
        if isinstance(props, dict):
            properties.extend(props.keys())
            # Handle nested objects
            for key, value in props.items():
                if isinstance(value, dict) and 'properties' in value:
                    nested_props = extract_schema_properties(value)
                    properties.extend([f"{key}.{prop}" for prop in nested_props])
        # Handle array items
        if 'items' in schema:
            items = schema['items']
            if isinstance(items, dict) and 'properties' in items:
                properties.extend(extract_schema_properties(items))
    return properties

def parse_swagger_spec(spec_source):
    """Parse Swagger/OpenAPI specification and extract endpoints with detailed parameters"""
    # Load specification
    if _is_url(spec_source):
        import requests
        response = requests.get(spec_source)
        if response.status_code == 200:
            if spec_source.endswith('.yaml') or spec_source.endswith('.yml'):
                import yaml
                spec_data = yaml.safe_load(response.text)
            else:
                spec_data = response.json()
        else:
            raise Exception(f"Failed to fetch Swagger spec: {response.status_code}")
    else:
        # Local file
        with open(spec_source, 'r', encoding='utf-8') as f:
            if spec_source.endswith('.yaml') or spec_source.endswith('.yml'):
                import yaml
                spec_data = yaml.safe_load(f)
            else:
                spec_data = json.load(f)
    
    endpoints = []
    paths = spec_data.get('paths', {})
    security_schemes = spec_data.get('components', {}).get('securitySchemes', {}) if 'components' in spec_data else spec_data.get('securityDefinitions', {})
    
    for path, path_item in paths.items():
        for method, operation in path_item.items():
            if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                # Extract parameters
                path_params = []
                query_params = []
                headers = []
                body_params = []
                body_type = None
                
                # Path and query parameters
                parameters = operation.get('parameters', [])
                for param in parameters:
                    if isinstance(param, dict):
                        param_in = param.get('in', '')
                        param_name = param.get('name', '')
                        if param_in == 'path':
                            path_params.append(param_name)
                        elif param_in == 'query':
                            query_params.append(param_name)
                        elif param_in == 'header':
                            headers.append(param_name)
                
                # Request body
                if 'requestBody' in operation:
                    request_body = operation['requestBody']
                    content = request_body.get('content', {})
                    if content:
                        content_type = list(content.keys())[0] if content.keys() else None
                        body_type = content_type
                        if content_type:
                            schema = content[content_type].get('schema', {})
                            body_params = extract_schema_properties(schema)
                elif 'parameters' in operation:
                    for param in operation['parameters']:
                        if isinstance(param, dict) and param.get('in') == 'body':
                            body_params.append('body_param')
                            schema = param.get('schema', {})
                            body_params.extend(extract_schema_properties(schema))
                
                # Authentication
                auth = 'None'
                if 'security' in operation:
                    for sec_requirement in operation['security']:
                        if isinstance(sec_requirement, dict):
                            for sec_name in sec_requirement.keys():
                                if sec_name in security_schemes:
                                    auth = security_schemes[sec_name].get('type', 'Custom')
                                    break
                
                endpoint_data = {
                    'method': method.upper(),
                    'path': path,
                    'description': operation.get('summary', operation.get('description', 'No description')),
                    'auth': auth,
                    'path_params': path_params,
                    'query_params': query_params,
                    'headers': headers,
                    'body_params': body_params,
                    'body_type': body_type
                }
                
                endpoints.append(endpoint_data)
    
    return endpoints

def _is_url(source):
    """Check if the source is a URL"""
    try:
        result = urlparse(source)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_security_rules():
    """Load security rules for test case generation"""
    return [
        # Injection Attacks
        {
            'id': 'SEC-SQLI-001',
            'title': 'SQL Injection Test',
            'description': 'Test endpoint for SQL injection vulnerabilities by injecting SQL payloads in parameters',
            'risk': 'High',
            'conditions': {
                'param_types': ['query_params', 'path_params', 'body_params'],
                'sensitive_params': ['id', 'user', 'search', 'filter', 'where', 'query', 'category', 'name']
            },
            'rationale': 'SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization. Attackers can manipulate the query structure to extract sensitive data, modify database contents, or execute administrative operations. This is particularly dangerous for endpoints handling user IDs, search terms, or filter parameters.',
            'impact': 'Data breach, unauthorized access to sensitive information, database manipulation, potential system compromise',
            'testing_steps': [
                '1. Identify all input parameters (query, path, body)',
                '2. Replace parameter values with SQL injection payloads',
                '3. Send the modified request',
                '4. Observe response for SQL errors or unexpected behavior',
                '5. Check if the payload altered the query logic'
            ],
            'payloads': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, username, password FROM users--",
                "1' ORDER BY 1--+",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'owasp_ref': 'API3:2023 - Injection'
        },
        {
            'id': 'SEC-CMDI-001',
            'title': 'Command Injection Test',
            'description': 'Test for command injection by injecting OS commands in parameters',
            'risk': 'Critical',
            'conditions': {
                'param_types': ['query_params', 'path_params', 'body_params'],
                'sensitive_params': ['file', 'path', 'cmd', 'exec', 'command', 'shell', 'ping', 'host']
            },
            'rationale': 'Command injection vulnerabilities occur when user input is passed directly to system commands or shell executions. This allows attackers to execute arbitrary operating system commands with the privileges of the application. Endpoints handling file operations, system commands, or network utilities are particularly vulnerable.',
            'impact': 'Complete system compromise, unauthorized file access, data exfiltration, malware installation, lateral movement',
            'testing_steps': [
                '1. Identify parameters that might interact with system commands',
                '2. Inject OS command payloads',
                '3. Monitor for command execution indicators',
                '4. Check response time delays',
                '5. Look for command output in responses'
            ],
            'payloads': [
                '; ls -la',
                '| cat /etc/passwd',
                '& ping -c 3 127.0.0.1',
                '&& whoami',
                '`id`'
            ],
            'owasp_ref': 'API3:2023 - Injection'
        },
        {
            'id': 'SEC-XSS-001',
            'title': 'Cross-Site Scripting (XSS) Test',
            'description': 'Test for XSS vulnerabilities by injecting script tags in input fields',
            'risk': 'Medium',
            'conditions': {
                'param_types': ['query_params', 'body_params'],
                'sensitive_params': ['search', 'query', 'name', 'title', 'description', 'comment', 'message']
            },
            'rationale': 'XSS occurs when user input is reflected back to users without proper encoding or sanitization. Attackers can inject malicious scripts that execute in victims\' browsers, leading to session hijacking, credential theft, or defacement. Input parameters that are displayed in web interfaces are particularly vulnerable.',
            'impact': 'Session hijacking, credential theft, defacement, phishing attacks, user impersonation',
            'testing_steps': [
                '1. Identify reflected or stored input parameters',
                '2. Inject XSS payloads in each parameter',
                '3. Submit the request',
                '4. Check if payload is reflected in response',
                '5. Verify if script execution is possible'
            ],
            'payloads': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '<svg/onload=alert(1)>',
                '"><script>alert(document.cookie)</script>'
            ],
            'owasp_ref': 'API3:2023 - Injection'
        },

        # Authentication and Authorization
        {
            'id': 'SEC-IDOR-001',
            'title': 'Insecure Direct Object Reference (IDOR) Test',
            'description': 'Test for IDOR by manipulating path parameters or object identifiers',
            'risk': 'High',
            'conditions': {
                'param_types': ['path_params'],
                'sensitive_params': ['id', 'user_id', 'order_id', 'product_id', 'account_id', 'resource_id']
            },
            'rationale': 'IDOR vulnerabilities occur when applications expose direct references to internal objects (like database IDs) without proper access controls. Attackers can enumerate and access unauthorized resources by guessing or incrementing object identifiers. Endpoints with numeric path parameters are particularly susceptible.',
            'impact': 'Unauthorized access to other users\' data, privacy violations, data theft, privilege escalation',
            'testing_steps': [
                '1. Identify numeric or predictable identifiers in URLs',
                '2. Modify the identifier values (increment/decrement)',
                '3. Access resources that should be restricted',
                '4. Compare responses with different identifiers',
                '5. Verify if unauthorized access is possible'
            ],
            'payloads': [
                '1, 2, 3, 4, 5',
                '00001, 00002',
                'user1, user2, user3',
                '../etc/passwd',
                'admin'
            ],
            'owasp_ref': 'API1:2023 - Broken Object Level Authorization'
        },
        {
            'id': 'SEC-AUTH-001',
            'title': 'Missing Authentication Test',
            'description': 'Verify that authentication is required for sensitive endpoints',
            'risk': 'High',
            'conditions': {
                'auth_required': False,
                'sensitive_paths': ['/admin', '/users', '/profile', '/orders', '/payment', '/account']
            },
            'rationale': 'Endpoints that lack proper authentication controls allow unauthorized access to sensitive functionality and data. This is critical for administrative interfaces, user profile management, payment processing, and personal data access. Attackers can exploit these endpoints to access, modify, or delete sensitive information.',
            'impact': 'Unauthorized data access, privilege escalation, data manipulation, system compromise',
            'testing_steps': [
                '1. Remove all authentication headers/tokens',
                '2. Send request to sensitive endpoints',
                '3. Check if 401/403 response is returned',
                '4. Verify access is properly denied',
                '5. Test with empty/invalid credentials'
            ],
            'payloads': [
                'Remove Authorization header',
                'Empty Bearer token',
                'Invalid API key',
                'No authentication at all',
                'Expired token'
            ],
            'owasp_ref': 'API2:2023 - Broken Authentication'
        },
        {
            'id': 'SEC-AUTHZ-001',
            'title': 'Privilege Escalation Test',
            'description': 'Test for horizontal/vertical privilege escalation',
            'risk': 'High',
            'conditions': {
                'methods': ['DELETE', 'PUT', 'PATCH', 'POST'],
                'sensitive_paths': ['/admin', '/users', '/roles', '/permissions', '/payment']
            },
            'rationale': 'Privilege escalation occurs when users can perform actions beyond their authorized permissions. Vertical escalation allows regular users to gain administrative privileges, while horizontal escalation allows access to other users\' resources. This is common in endpoints that modify user roles, permissions, or sensitive data.',
            'impact': 'Unauthorized administrative access, data manipulation, system compromise, unauthorized actions',
            'testing_steps': [
                '1. Perform action with regular user privileges',
                '2. Attempt same action on other users resources',
                '3. Try to access admin-only functionality',
                '4. Check if privilege checks are properly enforced',
                '5. Verify role-based access controls'
            ],
            'payloads': [
                'Access other user\'s data',
                'Modify admin settings',
                'Delete other user\'s resources',
                'Access restricted endpoints',
                'Change other user\'s permissions'
            ],
            'owasp_ref': 'API1:2023 - Broken Object Level Authorization'
        },

        # Input Validation and Data Handling
        {
            'id': 'SEC-MASS-ASSIGN-001',
            'title': 'Mass Assignment Test',
            'description': 'Test for mass assignment vulnerabilities by sending extra fields in request body',
            'risk': 'Medium',
            'conditions': {
                'param_types': ['body_params'],
                'sensitive_fields': ['admin', 'role', 'isadmin', 'is_admin', 'privilege', 'permission', 'verified', 'balance']
            },
            'rationale': 'Mass assignment vulnerabilities occur when applications automatically bind user input to internal object properties without proper filtering. Attackers can inject additional fields in requests to modify sensitive attributes like admin status, roles, or account balances. This is particularly dangerous in user registration or profile update endpoints.',
            'impact': 'Privilege escalation, unauthorized data modification, account takeover, financial fraud',
            'testing_steps': [
                '1. Examine request body structure',
                '2. Add sensitive fields not in original schema',
                '3. Send modified request',
                '4. Check if extra fields are processed',
                '5. Verify unauthorized data modification'
            ],
            'payloads': [
                '{"isAdmin": true}',
                '{"role": "administrator"}',
                '{"isVerified": true}',
                '{"balance": 999999}',
                '{"permissions": ["admin", "superuser"]}'
            ],
            'owasp_ref': 'API6:2023 - Mass Assignment'
        },
        {
            'id': 'SEC-OVERFLOW-001',
            'title': 'Buffer Overflow Test',
            'description': 'Test for buffer overflow by sending extremely large inputs',
            'risk': 'High',
            'conditions': {
                'param_types': ['query_params', 'body_params'],
                'sensitive_params': ['name', 'description', 'comment', 'message', 'search', 'query', 'data']
            },
            'rationale': 'Buffer overflow vulnerabilities occur when applications fail to properly validate input length, potentially leading to memory corruption. While less common in modern web applications, large inputs can still cause denial of service, application crashes, or in some cases, remote code execution. String parameters without length limits are particularly vulnerable.',
            'impact': 'Denial of service, application crashes, potential remote code execution, resource exhaustion',
            'testing_steps': [
                '1. Identify string input parameters',
                '2. Send extremely long input values',
                '3. Monitor for crashes or errors',
                '4. Check response time degradation',
                '5. Verify input length validation'
            ],
            'payloads': [
                'A' * 10000,
                'B' * 50000,
                'X' * 100000,
                'Lorem ipsum ' * 1000,
                '1234567890' * 5000
            ],
            'owasp_ref': 'API7:2023 - Identification and Authentication Failures'
        },

        # Rate Limiting and Resource Exhaustion
        {
            'id': 'SEC-RATE-LIMIT-001',
            'title': 'Rate Limiting Test',
            'description': 'Test for rate limiting by sending multiple requests in short time',
            'risk': 'Medium',
            'conditions': {
                'methods': ['POST', 'PUT', 'DELETE', 'PATCH'],
                'sensitive_paths': ['/login', '/auth', '/register', '/reset-password', '/payment']
            },
            'rationale': 'Endpoints without proper rate limiting are vulnerable to brute force attacks, credential stuffing, and denial of service. Authentication endpoints are particularly targeted as attackers can try millions of password combinations. Resource-intensive operations can also be exploited to exhaust system resources.',
            'impact': 'Account takeover, denial of service, resource exhaustion, credential theft',
            'testing_steps': [
                '1. Identify rate-limited endpoints',
                '2. Send rapid succession requests',
                '3. Monitor for 429 Too Many Requests',
                '4. Check if rate limiting is properly implemented',
                '5. Test different IP/user scenarios'
            ],
            'payloads': [
                '100 requests in 1 second',
                '1000 requests in 10 seconds',
                'Parallel requests from multiple threads',
                'Requests with different User-Agent headers',
                'Requests with rotating IP addresses'
            ],
            'owasp_ref': 'API4:2023 - Lack of Resources and Rate Limiting'
        },

        # File and Upload Security
        {
            'id': 'SEC-FILE-UPLOAD-001',
            'title': 'Malicious File Upload Test',
            'description': 'Test file upload endpoints for malicious file type acceptance',
            'risk': 'High',
            'conditions': {
                'param_types': ['body_params'],
                'sensitive_params': ['file', 'upload', 'image', 'document', 'attachment']
            },
            'rationale': 'Improper file upload validation can lead to remote code execution if malicious files are uploaded and executed. Attackers can upload web shells, malware, or scripts that bypass file type restrictions through double extensions, MIME type manipulation, or obfuscation. File upload endpoints without proper validation are high-risk targets.',
            'impact': 'Remote code execution, malware installation, server compromise, data exfiltration',
            'testing_steps': [
                '1. Identify file upload endpoints',
                '2. Try uploading malicious file types',
                '3. Test double extensions and MIME types',
                '4. Check file execution possibilities',
                '5. Verify proper file validation'
            ],
            'payloads': [
                'shell.php, shell.jsp, shell.asp',
                'image.jpg.php, doc.pdf.exe',
                'malicious_script.js',
                'webshell.aspx',
                'reverse_shell.py'
            ],
            'owasp_ref': 'API5:2023 - Broken Function Level Authorization'
        },
        {
            'id': 'SEC-PATH-TRAVERSAL-001',
            'title': 'Path Traversal Test',
            'description': 'Test for directory traversal vulnerabilities',
            'risk': 'High',
            'conditions': {
                'param_types': ['query_params', 'path_params'],
                'sensitive_params': ['file', 'path', 'filename', 'dir', 'directory', 'include', 'load']
            },
            'rationale': 'Path traversal vulnerabilities allow attackers to access files outside the intended directory structure. This can lead to sensitive file disclosure, including configuration files, source code, or system files. Parameters that specify file paths or names are particularly vulnerable if not properly sanitized.',
            'impact': 'Sensitive file disclosure, source code exposure, configuration file access, system information leakage',
            'testing_steps': [
                '1. Identify file path parameters',
                '2. Inject path traversal sequences',
                '3. Attempt to access system files',
                '4. Check for file disclosure',
                '5. Verify proper path validation'
            ],
            'payloads': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\cmd.exe',
                '../../../../../../../../etc/shadow',
                '..//..//..//..//etc/hosts',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd'
            ],
            'owasp_ref': 'API3:2023 - Injection'
        },

        # Business Logic and Workflow
        {
            'id': 'SEC-BUSINESS-LOGIC-001',
            'title': 'Business Logic Abuse Test',
            'description': 'Test for business logic flaws in workflow',
            'risk': 'Medium',
            'conditions': {
                'sensitive_paths': ['/order', '/payment', '/transfer', '/coupon', '/discount']
            },
            'rationale': 'Business logic vulnerabilities occur when applications fail to enforce proper workflow constraints or business rules. Attackers can manipulate multi-step processes, skip validation steps, reuse coupons, or perform actions out of sequence. These vulnerabilities are often overlooked because they don\'t fit traditional security categories.',
            'impact': 'Financial fraud, unauthorized transactions, service abuse, policy violations',
            'testing_steps': [
                '1. Map out the complete workflow for sensitive operations',
                '2. Attempt to skip or reorder workflow steps',
                '3. Test edge cases and boundary conditions',
                '4. Verify proper state management',
                '5. Check for transaction integrity'
            ],
            'payloads': [
                'Skip payment steps in checkout',
                'Reuse single-use coupons',
                'Transfer negative amounts',
                'Place orders with zero quantity',
                'Manipulate discount calculations'
            ],
            'owasp_ref': 'API8:2023 - Security Misconfiguration'
        },

        # Cryptographic and Transport Security
        {
            'id': 'SEC-HTTPS-001',
            'title': 'Insecure Transport Test',
            'description': 'Verify that sensitive endpoints require HTTPS',
            'risk': 'Medium',
            'conditions': {
                'auth_required': True,
                'sensitive_params': ['token', 'password', 'credit', 'ssn', 'card']
            },
            'rationale': 'Transmitting sensitive data over unencrypted HTTP connections exposes credentials, personal information, and session tokens to network eavesdropping. Even if HTTPS is available, applications must enforce its use for all sensitive operations. This is critical for authentication endpoints, payment processing, and personal data transmission.',
            'impact': 'Credential theft, session hijacking, data interception, privacy violations',
            'testing_steps': [
                '1. Attempt to access sensitive endpoints over HTTP',
                '2. Check if requests are redirected to HTTPS',
                '3. Verify HSTS headers are present',
                '4. Test mixed content scenarios',
                '5. Ensure all sensitive data is encrypted in transit'
            ],
            'payloads': [
                'Try HTTP instead of HTTPS',
                'Remove security headers',
                'Test certificate validation',
                'Check for mixed content',
                'Verify HSTS implementation'
            ],
            'owasp_ref': 'API7:2023 - Identification and Authentication Failures'
        },

        # API-Specific Issues
        {
            'id': 'SEC-API-ENUM-001',
            'title': 'API Endpoint Enumeration Test',
            'description': 'Test for hidden API endpoints discovery',
            'risk': 'Medium',
            'conditions': {
                'methods': ['GET'],
                'sensitive_paths': ['/api', '/v1', '/v2', '/admin']
            },
            'rationale': 'Hidden or undocumented API endpoints often lack proper security controls and can expose sensitive functionality. Attackers can enumerate API versions, administrative interfaces, or debug endpoints to discover vulnerable functionality. Well-structured APIs should have comprehensive endpoint inventories and proper access controls.',
            'impact': 'Unauthorized access to hidden functionality, data exposure, privilege escalation, system reconnaissance',
            'testing_steps': [
                '1. Enumerate common API paths and versions',
                '2. Test for hidden administrative endpoints',
                '3. Check for debug or development interfaces',
                '4. Verify all endpoints are properly documented',
                '5. Ensure proper access controls on all discovered endpoints'
            ],
            'payloads': [
                '/api/v1/admin',
                '/api/debug',
                '/api/internal',
                '/v2/admin/users',
                '/api/v1/hidden'
            ],
            'owasp_ref': 'API9:2023 - Improper Inventory Management'
        }
    ]

def generate_security_tests(endpoints):
    """Generate security test cases for each endpoint with parameter specificity"""
    rules = get_security_rules()
    
    def param_matches_sensitive(param_name, sensitive_list):
        """Check if parameter name matches sensitive patterns"""
        param_lower = param_name.lower()
        for sensitive in sensitive_list:
            if sensitive.lower() in param_lower:
                return True
        return False
    
    def endpoint_matches_sensitive_path(endpoint_path, sensitive_paths):
        """Check if endpoint path matches sensitive path patterns"""
        path_lower = endpoint_path.lower()
        for sensitive_path in sensitive_paths:
            if sensitive_path.lower() in path_lower:
                return True
        return False
    
    for endpoint in endpoints:
        security_tests = []
        relevant_params = []
        
        for rule in rules:
            conditions = rule['conditions']
            should_apply = False
            matched_params = []
            
            # Check parameter-based conditions
            if 'param_types' in conditions:
                param_types = conditions['param_types']
                sensitive_params = conditions.get('sensitive_params', [])
                
                # Check each parameter type
                for param_type in param_types:
                    if param_type in endpoint and endpoint[param_type]:
                        # Check if any parameters match sensitive patterns
                        if sensitive_params:
                            for param in endpoint[param_type]:
                                if param_matches_sensitive(param, sensitive_params):
                                    should_apply = True
                                    matched_params.append({
                                        'type': param_type,
                                        'name': param
                                    })
                        else:
                            # Apply to all parameters of this type if no sensitive params specified
                            should_apply = True
                            for param in endpoint[param_type]:
                                matched_params.append({
                                    'type': param_type,
                                    'name': param
                                })
            
            # Check authentication conditions
            elif 'auth_required' in conditions:
                if conditions['auth_required'] == False and endpoint.get('auth') == 'None':
                    if endpoint_matches_sensitive_path(endpoint.get('path', ''), conditions.get('sensitive_paths', [])):
                        should_apply = True
                elif conditions['auth_required'] == True and endpoint.get('auth') != 'None':
                    # Check for sensitive parameters that should be encrypted
                    for param_type in ['query_params', 'body_params', 'headers']:
                        if param_type in endpoint:
                            for param in endpoint[param_type]:
                                if param_matches_sensitive(param, conditions.get('sensitive_params', [])):
                                    should_apply = True
                                    matched_params.append({
                                        'type': param_type,
                                        'name': param
                                    })
            
            # Check method-based conditions
            elif 'methods' in conditions:
                if endpoint.get('method', '').upper() in [m.upper() for m in conditions['methods']]:
                    if endpoint_matches_sensitive_path(endpoint.get('path', ''), conditions.get('sensitive_paths', [])):
                        should_apply = True
            
            # Check sensitive fields in body
            elif 'sensitive_fields' in conditions and 'body_params' in endpoint:
                # This is for mass assignment - we'll flag it for manual review
                should_apply = True
            
            if should_apply:
                # Add matched parameters to relevant_params
                for param_info in matched_params:
                    param_key = f"{param_info['type']}:{param_info['name']}"
                    if param_key not in [p['key'] for p in relevant_params]:
                        relevant_params.append({
                            'key': param_key,
                            'type': param_info['type'],
                            'name': param_info['name']
                        })
                
                # Add rule details to test case
                test_case = {
                    'id': rule['id'],
                    'title': rule['title'],
                    'description': rule['description'],
                    'risk': rule['risk'],
                    'rationale': rule.get('rationale', 'No rationale provided'),
                    'impact': rule.get('impact', 'No impact information'),
                    'testing_steps': rule.get('testing_steps', ['Basic testing steps']),
                    'payloads': rule.get('payloads', [])[:10],  # Limit to top 10 payloads
                    'matched_params': matched_params,
                    'owasp_ref': rule.get('owasp_ref', 'N/A')
                }
                
                security_tests.append(test_case)
        
        endpoint['security_tests'] = security_tests
        endpoint['relevant_params'] = relevant_params
    
    return endpoints

def generate_html_report(endpoints_data, output_file="security_report.html"):
    """Generate HTML report from endpoints data"""
    
    # Read template
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Test Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .endpoint {
            background: white;
            margin-bottom: 30px;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
        }
        .endpoint h3 {
            color: #333;
            margin-top: 0;
            font-size: 1.5em;
        }
        .test-case {
            background: #f8f9fa;
            border-radius: 6px;
            padding: 20px;
            margin: 15px 0;
            border-left: 3px solid #ddd;
        }
        .test-case h4 {
            margin-top: 0;
            color: #495057;
        }
        .risk-critical {
            background-color: #c62828;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .risk-high {
            background-color: #d84315;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .risk-medium {
            background-color: #ef6c00;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .risk-low {
            background-color: #2e7d32;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        code {
            background-color: #e9ecef;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary h2 {
            color: #495057;
            margin-top: 0;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .payload-list {
            background: #e3f2fd;
            border-left: 3px solid #2196f3;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .steps-list {
            background: #f3e5f5;
            border-left: 3px solid #9c27b0;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .matched-params {
            background: #fff3e0;
            border-left: 3px solid #ff9800;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .params-section {
            background: #e8f5e8;
            border-left: 3px solid #4caf50;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .rationale-section {
            background: #f1f8e9;
            border-left: 3px solid #8bc34a;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .payload-list li, .steps-list li {
            margin: 5px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .risk-summary {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        a {
            color: #667eea;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        /* Smooth scrolling */
        html {
            scroll-behavior: smooth;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ API Security Test Report</h1>
        <p>Automated Security Test Cases for Your API Endpoints</p>
    </div>
    
    {{ENDPOINTS_CONTENT}}
    
    <div class="summary">
        <h2>📝 Next Steps</h2>
        <ul>
            <li>Review each security test case and implement the suggested tests</li>
            <li>Prioritize critical and high-risk vulnerabilities first</li>
            <li>Focus testing on the highlighted parameters for each endpoint</li>
            <li>Understand the exploit rationale to better assess risk</li>
            <li>Integrate these tests into your CI/CD pipeline</li>
            <li>Regularly regenerate this report when your API changes</li>
        </ul>
        <p><strong>Reference:</strong> OWASP API Security Top 10 (2023)</p>
    </div>
</body>
</html>"""
    
    # Generate summary statistics
    total_endpoints = len(endpoints_data)
    total_test_cases = sum(len(endpoint.get('security_tests', [])) for endpoint in endpoints_data)
    
    # Count endpoints by risk level
    risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    for endpoint in endpoints_data:
        for test_case in endpoint.get('security_tests', []):
            risk = test_case.get('risk', 'Low')
            if risk in risk_counts:
                risk_counts[risk] += 1
    
    # Generate summary table
    summary_table_html = f"""
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
            <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #1976d2;">{total_endpoints}</h3>
                <p style="margin: 5px 0 0 0;">Total Endpoints</p>
            </div>
            <div style="background: #ffebee; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #d32f2f;">{total_test_cases}</h3>
                <p style="margin: 5px 0 0 0;">Total Security Tests</p>
            </div>
            <div style="background: #fce4ec; padding: 15px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: #c2185b;">{risk_counts['Critical'] + risk_counts['High']}</h3>
                <p style="margin: 5px 0 0 0;">High Priority Issues</p>
            </div>
        </div>
    </div>
    
    <div class="summary">
        <h2>📋 Risk Distribution</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0;">
            <div style="background: #ffcdd2; padding: 15px; border-radius: 8px; text-align: center;">
                <h4 style="margin: 0; color: #c62828;">{risk_counts['Critical']}</h4>
                <p style="margin: 5px 0 0 0;">Critical</p>
            </div>
            <div style="background: #ffccbc; padding: 15px; border-radius: 8px; text-align: center;">
                <h4 style="margin: 0; color: #d84315;">{risk_counts['High']}</h4>
                <p style="margin: 5px 0 0 0;">High</p>
            </div>
            <div style="background: #fff3e0; padding: 15px; border-radius: 8px; text-align: center;">
                <h4 style="margin: 0; color: #ef6c00;">{risk_counts['Medium']}</h4>
                <p style="margin: 5px 0 0 0;">Medium</p>
            </div>
            <div style="background: #e8f5e8; padding: 15px; border-radius: 8px; text-align: center;">
                <h4 style="margin: 0; color: #2e7d32;">{risk_counts['Low']}</h4>
                <p style="margin: 5px 0 0 0;">Low</p>
            </div>
        </div>
    </div>
    """
    
    # Generate endpoints table with hyperlinks
    endpoints_table_html = """
    <div class="summary">
        <h2>📋 Endpoints Overview</h2>
        <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <thead>
                <tr style="background: #667eea; color: white;">
                    <th style="padding: 12px; text-align: left;">Endpoint</th>
                    <th style="padding: 12px; text-align: left;">Method</th>
                    <th style="padding: 12px; text-align: left;">Auth</th>
                    <th style="padding: 12px; text-align: left;">Test Cases</th>
                    <th style="padding: 12px; text-align: left;">Risk Summary</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for i, endpoint in enumerate(endpoints_data):
        # Create anchor ID for this endpoint
        endpoint_id = f"endpoint-{i}"
        
        test_cases = endpoint.get('security_tests', [])
        
        # Count risk levels
        critical_count = sum(1 for tc in test_cases if tc.get('risk') == 'Critical')
        high_count = sum(1 for tc in test_cases if tc.get('risk') == 'High')
        medium_count = sum(1 for tc in test_cases if tc.get('risk') == 'Medium')
        low_count = sum(1 for tc in test_cases if tc.get('risk') == 'Low')
        
        risk_summary = []
        if critical_count > 0:
            risk_summary.append(f'<span class="risk-critical">{critical_count} Critical</span>')
        if high_count > 0:
            risk_summary.append(f'<span class="risk-high">{high_count} High</span>')
        if medium_count > 0:
            risk_summary.append(f'<span class="risk-medium">{medium_count} Medium</span>')
        if low_count > 0:
            risk_summary.append(f'<span class="risk-low">{low_count} Low</span>')
        
        risk_summary_html = ', '.join(risk_summary) if risk_summary else 'None'
        
        # Create hyperlink to the endpoint section
        endpoint_link = f'<a href="#{endpoint_id}" style="color: #667eea; text-decoration: none; font-weight: bold;">{endpoint.get("path", "N/A")}</a>'
        
        endpoints_table_html += f"""
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 12px;">{endpoint_link}</td>
                    <td style="padding: 12px;"><code>{endpoint.get('method', 'N/A')}</code></td>
                    <td style="padding: 12px;">{endpoint.get('auth', 'None')}</td>
                    <td style="padding: 12px;">{len(test_cases)}</td>
                    <td style="padding: 12px;">{risk_summary_html}</td>
                </tr>
        """
    
    endpoints_table_html += """
            </tbody>
        </table>
    </div>
    """
    
    # Generate detailed endpoints HTML - INCLUDING ALL ENDPOINTS
    detailed_endpoints_html = ""
    for i, endpoint in enumerate(endpoints_data):
        # Create anchor ID for this endpoint
        endpoint_id = f"endpoint-{i}"
        
        # Generate relevant parameters section
        relevant_params = endpoint.get('relevant_params', [])
        params_html = ""
        if relevant_params:
            params_html = "<div class='params-section'><h4>🎯 Relevant Parameters for Testing:</h4><ul>"
            for param in relevant_params:
                params_html += f"<li><strong>{param['name']}</strong> ({param['type'].replace('_', ' ').title()})</li>"
            params_html += "</ul></div>"
        
        test_cases_html = ""
        test_cases = endpoint.get('security_tests', [])
        
        # Process ALL test cases for this endpoint
        for j, test_case in enumerate(test_cases):
            # Generate steps HTML
            steps_html = "<ol>"
            for step in test_case.get('testing_steps', []):
                steps_html += f"<li>{step}</li>"
            steps_html += "</ol>"
            
            # Generate payloads HTML
            payloads_html = "<ul>"
            for payload in test_case.get('payloads', [])[:8]:  # Limit to 8 payloads
                payloads_html += f"<li><code>{payload}</code></li>"
            payloads_html += "</ul>"
            
            # Generate matched parameters section
            matched_params_html = ""
            matched_params = test_case.get('matched_params', [])
            if matched_params:
                matched_params_html = "<div class='matched-params'><p><strong>Parameters to Test:</strong> "
                param_names = [f"<code>{param['name']}</code>" for param in matched_params]
                matched_params_html += ", ".join(param_names) + "</p></div>"
            
            # Generate rationale and impact sections
            rationale_html = f"""
            <div class="rationale-section">
                <p><strong>🔍 Exploit Rationale:</strong> {test_case.get('rationale', 'No rationale provided')}</p>
                <p><strong>💥 Potential Impact:</strong> {test_case.get('impact', 'No impact information')}</p>
            </div>
            """
            
            test_cases_html += f"""
            <div class="test-case">
                <h4>{test_case['title']}</h4>
                <p><strong>Risk Level:</strong> <span class="risk-{test_case['risk'].lower()}">{test_case['risk']}</span></p>
                <p><strong>Description:</strong> {test_case['description']}</p>
                {rationale_html}
                {matched_params_html}
                <p><strong>OWASP Reference:</strong> {test_case.get('owasp_ref', 'N/A')}</p>
                <div class="steps-list">
                    <strong>Testing Steps:</strong>
                    {steps_html}
                </div>
                <div class="payload-list">
                    <strong>Payloads to Test:</strong>
                    {payloads_html}
                </div>
            </div>
            """
        
        # Add section header with anchor
        detailed_endpoints_html += f"""
        <div class="endpoint" id="{endpoint_id}">
            <h3>{endpoint['method']} {endpoint['path']}</h3>
            <p><strong>Description:</strong> {endpoint.get('description', 'No description')}</p>
            <p><strong>Authentication:</strong> {endpoint.get('auth', 'None')}</p>
            {params_html}
            <h4>Security Test Cases ({len(test_cases)}):</h4>
            {test_cases_html if test_cases_html else '<p>No security test cases identified for this endpoint.</p>'}
        </div>
        """
    
    # Combine all sections
    full_content = summary_table_html + endpoints_table_html + detailed_endpoints_html
    
    # Replace placeholder with actual content
    html_content = html_template.replace("{{ENDPOINTS_CONTENT}}", full_content)
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Security report generated: {output_file}")
    return output_file

def main():
    parser = argparse.ArgumentParser(description='API Security Test Case Generator')
    parser.add_argument('--postman', help='Path to Postman collection JSON file')
    parser.add_argument('--swagger', help='URL or path to Swagger/OpenAPI specification')
    parser.add_argument('--output', default='security_report.html', help='Output HTML file name')
    
    args = parser.parse_args()
    
    if not args.postman and not args.swagger:
        print("❌ Please provide either --postman or --swagger argument")
        sys.exit(1)
    
    endpoints_data = []
    
    try:
        if args.postman:
            print("🔍 Parsing Postman collection...")
            endpoints_data = parse_postman_collection(args.postman)
            
        elif args.swagger:
            print("🔍 Parsing Swagger/OpenAPI specification...")
            endpoints_data = parse_swagger_spec(args.swagger)
        
        print("🛡️  Generating security test cases...")
        endpoints_with_tests = generate_security_tests(endpoints_data)
        
        print("📄 Generating HTML report...")
        report_file = generate_html_report(endpoints_with_tests, args.output)
        
        # Open in browser
        webbrowser.open('file://' + os.path.realpath(report_file))
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
