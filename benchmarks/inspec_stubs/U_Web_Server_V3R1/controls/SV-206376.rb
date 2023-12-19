control 'SV-206376' do
  title 'The web server must not be a proxy server.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended.  Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server is also a proxy server.

If the web server is also acting as a proxy server, this is a finding.'
  desc 'fix', 'Uninstall any proxy services, modules, and libraries that are used by the web server to act as a proxy server.

Verify all configuration changes are made to assure the web server is no longer acting as a proxy server in any manner.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6637r377720_chk'
  tag severity: 'medium'
  tag gid: 'V-206376'
  tag rid: 'SV-206376r395853_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000076'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6637r377721_fix'
  tag 'documentable'
  tag legacy: ['SV-54271', 'V-41694']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
