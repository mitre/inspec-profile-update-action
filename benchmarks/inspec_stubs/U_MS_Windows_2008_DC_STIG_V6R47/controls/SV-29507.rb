control 'SV-29507' do
  title 'ACLs for system files and directories do not conform to minimum requirements.'
  desc 'Failure to properly configure file and directory permissions (ACLs) allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.'
  desc 'check', 'The default ACL settings are adequate when the Security Option “Network access: Let everyone permissions apply to anonymous users” is set to “Disabled” (V-3377) and Power User Group Membership is restricted.  If the default ACLs are maintained, the referenced option is set to “Disabled” and Powers Users are restricted, this check should normally be marked not a finding.

The Power Users group is included in later Windows versions for backward compatibility.

If an ACL setting prevents a site’s applications from performing properly, the site can modify that specific setting. Settings should only be changed to the minimum necessary for the application to function. Each exception to the recommended settings should be documented and kept on file by the IAO.'
  desc 'fix', 'Maintain the default file ACLs, configure the Security Option: “Network access: Let everyone permissions apply to anonymous users” to “Disabled” (V-3377) and restrict the Power Users group to include no members.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-39090r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1130'
  tag rid: 'SV-29507r1_rule'
  tag gtitle: 'System File ACLs'
  tag fix_id: 'F-29104r1_fix'
  tag false_positives: 'If a manual check of a questionable ACL setting shows that it has been set to meet or is more restrictive than minimum requirements, then it will not be counted as a finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
