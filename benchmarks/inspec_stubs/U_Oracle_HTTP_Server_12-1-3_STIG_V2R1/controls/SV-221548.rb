control 'SV-221548' do
  title 'OHS must have the ServerTokens directive set to limit the response header.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ServerTokens" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "Custom DoD-Web-Server", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ServerTokens" directive at the OHS server configuration scope.

3. Set the "ServerTokens" directive to a value of "Custom DoD-Web-Server", add the directive if it does not exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23263r415323_chk'
  tag severity: 'low'
  tag gid: 'V-221548'
  tag rid: 'SV-221548r415325_rule'
  tag stig_id: 'OH12-1X-000348'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-23252r415324_fix'
  tag 'documentable'
  tag legacy: ['SV-78971', 'V-64481']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
