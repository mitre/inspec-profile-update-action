control 'SV-33018' do
  title 'The number of allowed simultaneous requests must be set.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include, where feasible, limiting parameter values associated with keepalive, (i.e., a parameter used to limit the amount of time a connection may be inactive).'
  desc 'check', 'To view the MaxKeepAliveRequests value, enter the following command: 

grep "MaxKeepAliveRequests" /usr/local/apache2/conf/httpd.conf 

If the returned value of MaxKeepAliveRequests is not set to 100 or greater, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and set the MaxKeepAliveRequests directive to 100 or greater.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33700r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2240'
  tag rid: 'SV-33018r1_rule'
  tag stig_id: 'WG110 A22'
  tag gtitle: 'WG110'
  tag fix_id: 'F-29334r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
