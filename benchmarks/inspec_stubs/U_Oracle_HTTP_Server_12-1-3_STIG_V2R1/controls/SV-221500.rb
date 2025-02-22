control 'SV-221500' do
  title 'OHS must have the KeepAliveTimeout properly set to restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "KeepAliveTimeout" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is set greater than 5, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "KeepAliveTimeout" directive at the OHS server and virtual host configuration scopes.

3. Set the "KeepAliveTimeout" directive to a value of "5", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23215r415183_chk'
  tag severity: 'medium'
  tag gid: 'V-221500'
  tag rid: 'SV-221500r415185_rule'
  tag stig_id: 'OH12-1X-000285'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-23204r415184_fix'
  tag 'documentable'
  tag legacy: ['SV-78949', 'V-64459']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
