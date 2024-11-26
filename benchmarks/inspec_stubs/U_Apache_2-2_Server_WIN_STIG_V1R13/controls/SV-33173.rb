control 'SV-33173' do
  title 'The web server must not be configured as a proxy server.'
  desc 'The Apache proxy modules allow the server to act as a proxy (either forward or reverse proxy) of http and other protocols with additional proxy modules loaded. If the Apache installation is not intended to proxy requests to or from another network then the proxy module should not be loaded. Proxy servers can act as an important security control when properly configured, however a secure proxy server is not within the scope of this STIG. A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests is a very common attack, as proxy servers are useful for anonymizing attacks on other servers, or possibly proxying requests into an otherwise protected network.'
  desc 'check', 'Note: If the Apache web server is only performing in a proxy server role and does not host any websites nor support any applications, this check is Not Applicable.
Open a command prompt window.

Navigate to the “bin” directory (in many cases this may be [Drive Letter]:\\[directory path]\\Apache Software Foundation\\Apache2.2\\bin>).

Enter the following command: httpd –M <enter>
Note: Some installations may be running under apache.exe. In such case, validate by running the following command: apache -M <enter>

This will provide a list of all loaded modules. If any of the following modules are found this is a finding: proxy_module, proxy_ajp_module, proxy_balancer_module, proxy_ftp_module, proxy_http_module, or proxy_connect_module.'
  desc 'fix', 'Disable all proxy modules by adding a "#" in front of them within the httpd.conf file, and restarting the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33809r5_chk'
  tag severity: 'medium'
  tag gid: 'V-26299'
  tag rid: 'SV-33173r3_rule'
  tag stig_id: 'WA00520 W22'
  tag gtitle: 'WA00520'
  tag fix_id: 'F-29459r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
