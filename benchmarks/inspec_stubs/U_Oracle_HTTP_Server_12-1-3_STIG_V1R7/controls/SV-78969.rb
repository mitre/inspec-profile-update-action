control 'SV-78969' do
  title 'OHS must have the ServerSignature directive disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "ServerSignature" directive at the OHS server, virtual host, and directory configuration scopes.

3. If the directive is omitted or is not set to "Off", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "ServerSignature" directive at the OHS server, virtual host, and directory configuration scopes.

3. Set the "ServerSignature" directive to a value of "Off", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64479'
  tag rid: 'SV-78969r1_rule'
  tag stig_id: 'OH12-1X-000347'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-70409r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
