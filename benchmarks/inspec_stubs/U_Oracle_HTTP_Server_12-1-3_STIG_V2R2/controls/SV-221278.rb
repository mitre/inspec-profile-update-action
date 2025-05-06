control 'SV-221278' do
  title 'OHS must have the SSLFIPS directive enabled to encrypt remote connections in accordance with the categorization of data hosted by the web server.'
  desc 'The web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

Methods of communication are http for publicly displayed information, https to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-22993r414517_chk'
  tag severity: 'high'
  tag gid: 'V-221278'
  tag rid: 'SV-221278r879519_rule'
  tag stig_id: 'OH12-1X-000008'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-22982r414518_fix'
  tag 'documentable'
  tag legacy: ['SV-78625', 'V-64135']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
