control 'SV-9045' do
  title 'Membership in the Group Policy Creator Owners and Incoming Forest Trust Builders groups must be limited.'
  desc 'Membership in the Group Policy Creator Owners and Incoming Forest Trust Builders groups assigns a high privilege level for AD functions.  Unnecessary membership increases the risk from compromise or unintended updates.  Members of these groups must specifically require those privileges and be documented.'
  desc 'check', 'Start "Active Directory Users and Computers" (Available from various menus or run "dsa.msc").

Review the membership of the "Incoming Forest Trust Builders" group.

Navigate to the "Built-in" container.

Right-click on the "Incoming Forest Trust Builders", select "Properties" and then the "Members" tab.

If any accounts are not documented as necessary with the ISSO, this is a finding.

Review the membership of the "Group Policy Creator Owner" group.

Navigate to the "Users" container.

Right-click on the "Group Policy Creator Owner", select "Properties" and then the "Members" tab.

If any accounts are not documented as necessary with the ISSO, this is a finding.

It is possible to move some system-defined groups from their default locations.  If a group is not in the location noted, review other containers to locate.'
  desc 'fix', 'Document membership of the Group Policy Creator Owners and Incoming Forest Trust Builders groups.  Remove any accounts that do not require the privileges these groups assign.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-72971r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8548'
  tag rid: 'SV-9045r3_rule'
  tag stig_id: 'AD.0240'
  tag gtitle: 'AD.0240'
  tag fix_id: 'F-79271r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Manager'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
