control 'SV-58415' do
  title 'A group must be defined on domain systems to include all local administrator accounts.'
  desc 'Several user rights on domain systems require that local administrator accounts be assigned to them.  This is separate from the built-in Administrators group, which also contains domain administrative accounts/groups.  Defining a consistent group name allows compliance to be more easily determined.'
  desc 'fix', 'This requirement is NA for non domain-joined systems.

Create a local group with the name "DenyNetworkAccess" or "DeniedNetworkAccess" on the system.
Include all local administrator accounts as members of the group, including the built-in Administrator account.  Do not include domain administrative accounts or groups.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
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
