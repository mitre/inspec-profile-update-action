control 'SV-32844' do
  title 'The KeepAlive directive must be enabled.'
  desc 'The KeepAlive extension to HTTP/1.0 and the persistent connection feature of HTTP/1.1 provide long lived HTTP sessions which allow multiple requests to be sent over the same connection. These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'To view the KeepAlive value enter the following command:

grep "KeepAlive" /usr/local/apache2/conf/httpd.conf.

Verify the Value of KeepAlive is set to “On” If not, this is a finding. 

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for not using persistent connections. If the site has this documentation, this should be marked as Not a Finding.'
  desc 'fix', 'Edit the httpd.conf file and set the value of "KeepAlive" to "On"'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-10977r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13725'
  tag rid: 'SV-32844r2_rule'
  tag stig_id: 'WA000-WWA022 A22'
  tag gtitle: 'WA000-WWA022'
  tag fix_id: 'F-13173r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
