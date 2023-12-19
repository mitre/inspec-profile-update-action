control 'SV-87487' do
  title 'Membership to the Schema Admins group must be limited.'
  desc 'The Schema Admins group is a privileged group in a forest root domain.  Members of the Schema Admins group can make changes to the schema, which is the framework for the Active Directory forest.  Changes to the schema are not frequently required.  This group only contains the Built-in Administrator account by default.  Additional accounts must only be added when changes to the schema are necessary and then must be removed.'
  desc 'check', 'Open "Active Directory Users and Computers" on a domain controller in the forest root domain.

Navigate to the "Users" container.

Right-click on "Schema Admins" and select "Properties", and then select the "Members" tab.

If any accounts other than the built-in Administrators group are members, verify their necessity with the ISSO.

If any accounts are members of the group when schema changes are not being made, this is a finding.'
  desc 'fix', 'Limit membership in the Schema Admins group to only those accounts necessary during a schema update.  Remove accounts when the updates are complete.  Document accounts necessary during schema updates with the ISSO.'
  impact 0.5
  ref 'DPMS Target Active Directory Forest'
  tag check_id: 'C-72961r2_chk'
  tag severity: 'medium'
  tag gid: 'V-72835'
  tag rid: 'SV-87487r1_rule'
  tag stig_id: 'AD.0017'
  tag gtitle: 'AD.0017'
  tag fix_id: 'F-79269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
