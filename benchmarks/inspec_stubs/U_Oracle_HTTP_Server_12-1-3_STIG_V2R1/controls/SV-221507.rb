control 'SV-221507' do
  title 'OHS must have the LimitXMLRequestBody directive set to restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "LimitXMLRequestBody" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is set greater than 10240, this is a finding.

Note: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of a higher value.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "LimitXMLRequestBody" directive at the OHS server and virtual host configuration scopes.

3. Set the "LimitXMLRequestBody" directive to a value of "10240", add the directive if it does not exist.

Note: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of a higher value.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23222r415204_chk'
  tag severity: 'medium'
  tag gid: 'V-221507'
  tag rid: 'SV-221507r415206_rule'
  tag stig_id: 'OH12-1X-000292'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-23211r415205_fix'
  tag 'documentable'
  tag legacy: ['SV-78963', 'V-64473']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
