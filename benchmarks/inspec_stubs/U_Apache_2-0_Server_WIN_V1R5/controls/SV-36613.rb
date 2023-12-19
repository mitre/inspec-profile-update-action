control 'SV-36613' do
  title 'The web server must not be configured as a proxy server.'
  desc 'The Apache proxy modules allow the server to act as a proxy (either forward or reverse proxy) of http and other protocols with additional proxy modules loaded. If the Apache installation is not intended to proxy requests to or from another network then the proxy module should not be loaded. Proxy servers can act as an important security control when properly configured, however a secure proxy server is not within the scope of this STIG. A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests is a very common attack, as proxy servers are useful for anonymizing attacks on other servers, or possibly proxying requests into an otherwise protected network.'
  desc 'check', 'Open the httpd.conf file. 

Search for the following uncommented LoadModule directive statements:  proxy_module, proxy_ajp_module, proxy_balancer_module, proxy_ftp_module, proxy_http_module, or proxy_connect_module.

If any of these statements are found uncommented, this is a finding.'
  desc 'fix', 'Disable all proxy modules by adding a "#" in front of them within the httpd.conf file, and restarting the Apache httpd service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-35708r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26299'
  tag rid: 'SV-36613r1_rule'
  tag stig_id: 'WA00520 W20'
  tag gtitle: 'WA00520'
  tag fix_id: 'F-30950r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1, ECND-2'
end
