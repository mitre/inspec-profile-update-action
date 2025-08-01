control 'SV-32980' do
  title 'The Timeout directive must be properly set.'
  desc 'These Timeout requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Timeout

Every enabled Timeout directive value needs to be 300 or less. If any directive is set improperly, this is a finding.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has an operational reason for the use of an increased value. If the site has this documented, this should be marked as Not a Finding.'
  desc 'fix', 'Modify the Timeout directive in the applicable Apache configuration files to have a value of 300 seconds or less.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33660r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13724'
  tag rid: 'SV-32980r2_rule'
  tag stig_id: 'WA000-WWA020 W22'
  tag gtitle: 'WA000-WWA020'
  tag fix_id: 'F-29296r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
