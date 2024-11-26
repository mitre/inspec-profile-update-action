control 'SV-32511' do
  title 'ACLs for system files and directories will conform to minimum requirements.'
  desc 'Failure to properly configure ACL file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.'
  desc 'check', 'The default ACL settings are adequate when the Security Option “Network access: Let everyone permissions apply to anonymous users” is set to “Disabled” (V-3377). If the default ACLs are maintained and the referenced option is set to “Disabled”, this check should normally be marked “Not a Finding”.

Note:  If an ACL setting prevents a site’s applications from performing properly, the site can modify that specific setting. Settings should only be changed to the minimum necessary for the application to function. Each exception to the recommended settings should be documented and kept on file by the IAO.'
  desc 'fix', 'Maintain the default file ACLs and configure the Security Option: “Network access: Let everyone permissions apply to anonymous users” to “Disabled” (V-3377).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1130'
  tag rid: 'SV-32511r1_rule'
  tag gtitle: 'System File ACLs'
  tag fix_id: 'F-28932r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
