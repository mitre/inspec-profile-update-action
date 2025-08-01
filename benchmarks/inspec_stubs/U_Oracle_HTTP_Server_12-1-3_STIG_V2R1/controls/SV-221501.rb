control 'SV-221501' do
  title 'OHS must have the MaxKeepAliveRequests directive properly set to restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "MaxKeepAliveRequests" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is set greater than 500, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "MaxKeepAliveRequests" directive at the OHS server and virtual host configuration scopes.

3. Set the "MaxKeepAliveRequests" directive to a value of "500", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23216r415186_chk'
  tag severity: 'medium'
  tag gid: 'V-221501'
  tag rid: 'SV-221501r415188_rule'
  tag stig_id: 'OH12-1X-000286'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-23205r415187_fix'
  tag 'documentable'
  tag legacy: ['SV-78951', 'V-64461']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
