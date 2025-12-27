control 'SV-58415' do
  title 'A group must be defined on domain systems to include all local administrator accounts.'
  desc 'Several user rights on domain systems require that local administrator accounts be assigned to them.  This is separate from the built-in Administrators group, which also contains domain administrative accounts/groups.  Defining a consistent group name allows compliance to be more easily determined.'
  desc 'check', 'This requirement is NA for non domain-joined systems.

Review local groups on the system.

Documentation and scripts supporting the creation of this group to restrict local administrative accounts were changed at one point.  The original name, "DeniedNetworkAccess", was changed to "DenyNetworkAccess".  Automated benchmarks will look for either of these groups.

If the group "DenyNetworkAccess" or "DeniedNetworkAccess" does not exist, this is a finding.

Compare the membership of the defined group with the local Administrators group.
Verify the group includes all local administrator accounts as members.
This includes the built-in Administrator account.  It does not include domain administrative accounts or groups.

If the group "DenyNetworkAccess" or "DeniedNetworkAccess" does not include all local administrator accounts, this is a finding.'
  desc 'fix', 'This requirement is NA for non domain-joined systems.

Create a local group with the name "DenyNetworkAccess" or "DeniedNetworkAccess" on the system.
Include all local administrator accounts as members of the group, including the built-in Administrator account.  Do not include domain administrative accounts or groups.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58029r2_chk'
  tag severity: 'low'
  tag gid: 'V-45589'
  tag rid: 'SV-58415r2_rule'
  tag stig_id: 'WINGE-000200'
  tag gtitle: 'WINGE-000200'
  tag fix_id: 'F-62391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
