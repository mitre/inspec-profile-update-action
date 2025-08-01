control 'SV-33105' do
  title 'The number of allowed simultaneous requests must be set.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive, (i.e., a parameter used to limit the amount of time a connection may be inactive).'
  desc 'check', 'NOTE: This setting must be explicitly set.

Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: MaxKeepAliveRequests

Every enabled MaxKeepAliveRequests value needs to be 100 or greater. If any directive is less than 100, this is a finding.'
  desc 'fix', 'Set the MaxKeepAliveRequests directive to 100 or greater.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33766r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2240'
  tag rid: 'SV-33105r2_rule'
  tag stig_id: 'WG110 W22'
  tag gtitle: 'WG110'
  tag fix_id: 'F-29403r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
