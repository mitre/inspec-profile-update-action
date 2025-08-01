control 'SV-237423' do
  title 'Members of the SCOM Administrators Group must be reviewed to ensure access is still required.'
  desc 'When people leave their roles, their group memberships are often times not updated.'
  desc 'check', 'From Active Directory Users and Computers, search for the group containing SCOM administrators. Review the users who are listed in this group. If any user in this group is no longer with the organization, no longer requires SCOM administration rights, or is no longer in a SCOM administration role within the organization, this is a finding.'
  desc 'fix', 'From Active Directory Users and Computers, search for the group containing SCOM administrators. Double-click on the group and select the members tab. For each user that no longer needs rights, select the account and click the Remove button. Click OK once finished.'
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40642r643913_chk'
  tag severity: 'medium'
  tag gid: 'V-237423'
  tag rid: 'SV-237423r643915_rule'
  tag stig_id: 'SCOM-AC-000001'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-40605r643914_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
