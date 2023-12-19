control 'SV-78977' do
  title 'OHS must have defined error pages for common error codes that minimize the identity of the web server, patches, loaded modules, and directory paths.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for "ErrorDocument" directives at the OHS server, virtual host, and directory configuration scopes.

3. If the directives are omitted or set improperly for HTTP errors 400, 401, 403 - 405, 408, 410 - 415, 500 - 503, or 506, this is a finding.

4. Validate that the folder and files where the "ErrorDocument" directive are pointing are valid. If the folder or file is not valid, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for "ErrorDocument" directives at the OHS server, virtual host, and directory configuration scopes.

3. Set the "ErrorDocument" directives for HTTP errors 400, 401, 403 - 405, 408, 410 - 415, 500 - 503, and 506 (e.g., ErrorDocument 400 HTTP_BAD_REQUEST_en.html) to files that minimize the identity of the web server, patches, loaded modules, and directory paths, add the directive if it does not exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65239r1_chk'
  tag severity: 'low'
  tag gid: 'V-64487'
  tag rid: 'SV-78977r1_rule'
  tag stig_id: 'OH12-1X-000351'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-70417r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
