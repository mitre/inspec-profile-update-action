control 'SV-32880' do
  title 'The KeepAliveTimeout directive must be defined.'
  desc 'The number of seconds Apache will wait for a subsequent request before closing the connection. Once a request has been received, the timeout value specified by the Timeout directive applies. Setting KeepAliveTimeout to a high value may cause performance problems in heavily loaded servers. The higher the timeout, the more server processes will be kept occupied waiting on connections with idle clients. These requirements are set to mitigate the effects of several types of denial of service attacks.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: KeepAliveTimeout

If any directive is not set to 15 or less, this is a finding.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has an operational reason for not using persistent connections. If the site has this documented, this should be marked as Not a Finding.'
  desc 'fix', 'Modify the KeepAliveTimeout directive in the applicable Apache configuration files to have a value of 15 or less.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33611r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13726'
  tag rid: 'SV-32880r2_rule'
  tag stig_id: 'WA000-WWA024 W22'
  tag gtitle: 'WA000-WWA024'
  tag fix_id: 'F-29218r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
