control 'SV-32987' do
  title 'The KeepAlive directive must be enabled.'
  desc 'The KeepAlive extension to HTTP/1.0 and the persistent connection feature of HTTP/1.1 provide long lived HTTP sessions which allow multiple requests to be sent over the same connection. These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: KeepAlive

Every enabled KeepAlive value needs to be set to “On”. If any directive is set improperly, this is a finding. If any directive is set to “Off”, this is a finding.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has an operational reason for not using persistent connections. If the site has this documented, this should be marked as Not a Finding.'
  desc 'fix', 'Modify the KeepAlive directive in the applicable Apache configuration files to have a value of On.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33661r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13725'
  tag rid: 'SV-32987r2_rule'
  tag stig_id: 'WA000-WWA022 W22'
  tag gtitle: 'WA000-WWA022'
  tag fix_id: 'F-29298r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
