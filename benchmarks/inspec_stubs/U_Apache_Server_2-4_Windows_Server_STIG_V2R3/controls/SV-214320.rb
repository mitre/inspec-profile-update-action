control 'SV-214320' do
  title 'The Apache web server must not be a proxy server.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack, making the attack anonymous.'
  desc 'check', %q(In a command line, CD to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If any of the following modules are present, this is a finding:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module)
  desc 'fix', "Edit the <'INSTALL PATH'>\\conf\\httpd.conf file and remove the following modules:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module"
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15532r277463_chk'
  tag severity: 'medium'
  tag gid: 'V-214320'
  tag rid: 'SV-214320r879587_rule'
  tag stig_id: 'AS24-W1-000260'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-15530r277464_fix'
  tag 'documentable'
  tag legacy: ['SV-102461', 'V-92373']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
