control 'SV-32877' do
  title 'The KeepAliveTimeout directive must be defined.'
  desc 'The number of seconds Apache will wait for a subsequent request before closing the connection. Once a request has been received, the timeout value specified by the Timeout directive applies. Setting KeepAliveTimeout to a high value may cause performance problems in heavily loaded servers. The higher the timeout, the more server processes will be kept occupied waiting on connections with idle clients. These requirements are set to mitigate the effects of several types of denial of service attacks.'
  desc 'check', 'To view the KeepAliveTimeout value enter the following command:

grep "KeepAliveTimeout" /usr/local/apache2/conf/httpd.conf.

If the value of "KeepAliveTimeout" is not set to 15 or less, this is a finding.

Note: If the directive does not exist, this is not a finding because it will default to 5. It is recommended that the directive be explicitly set to prevent unexpected results should the defaults for any reason change(i.e. software update).'
  desc 'fix', 'Edit the httpd.conf file and set the value of "KeepAliveTimeout" to the value of 15 or less.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33610r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13726'
  tag rid: 'SV-32877r1_rule'
  tag stig_id: 'WA000-WWA024 A22'
  tag gtitle: 'WA000-WWA024'
  tag fix_id: 'F-29216r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
