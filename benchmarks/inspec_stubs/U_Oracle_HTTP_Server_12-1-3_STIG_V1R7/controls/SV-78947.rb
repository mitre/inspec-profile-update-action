control 'SV-78947' do
  title 'OHS must have the KeepAlive directive properly set to restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "KeepAlive" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "KeepAlive" directive at the OHS server and virtual host configuration scopes.

3. Set the "KeepAlive" directive to a value of "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65209r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64457'
  tag rid: 'SV-78947r1_rule'
  tag stig_id: 'OH12-1X-000284'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-70387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
