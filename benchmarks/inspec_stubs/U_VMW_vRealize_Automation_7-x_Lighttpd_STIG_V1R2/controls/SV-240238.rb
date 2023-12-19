control 'SV-240238' do
  title 'Lighttpd proxy settings must be configured.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.'
  desc 'check', 'At the command prompt, execute the following command:

grep -A 6 -B 1 proxy.server /opt/vmware/etc/lighttpd/lighttpd.conf

If the proxy.server "host" value is not set to "127.0.0.1" and the proxy.server "port" value is not set to "5488", this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to proxy.server. Set the proxy.server "host" value to "127.0.0.1" and the proxy.server "port" value to "5488".

Note: The proxy.server section should look like this when it is configured:

$HTTP["url"] =~ "^/cimom" {
    proxy.server = ( "" =>
                    ((
                      "host" => "127.0.0.1",
                      "port" => "5488"
                    ))
                   )
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43471r668031_chk'
  tag severity: 'medium'
  tag gid: 'V-240238'
  tag rid: 'SV-240238r879587_rule'
  tag stig_id: 'VRAU-LI-000165'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-43430r668032_fix'
  tag 'documentable'
  tag legacy: ['SV-100983', 'V-90333']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
