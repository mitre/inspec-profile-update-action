control 'SV-33220' do
  title 'The web server must not be configured as a proxy server.'
  desc 'The Apache proxy modules allow the server to act as a proxy (either forward or reverse proxy) of http and other protocols with additional proxy modules loaded. If the Apache installation is not intended to proxy requests to or from another network then the proxy module should not be loaded. Proxy servers can act as an important security control when properly configured, however a secure proxy server is not within the scope of this STIG. A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests is a very common attack, as proxy servers are useful for anonymizing attacks on other servers, or possibly proxying requests into an otherwise protected network.'
  desc 'check', 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If any of the following modules are found this is a finding:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module'
  desc 'fix', 'Edit the httpd.conf file and remove the following modules:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33762r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26299'
  tag rid: 'SV-33220r1_rule'
  tag stig_id: 'WA00520 A22'
  tag gtitle: 'WA00520'
  tag fix_id: 'F-29398r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1, ECND-2'
end
