control 'SV-78439' do
  title 'The vCenter Server users must have the correct roles assigned.'
  desc 'Users and service accounts must only be assigned privileges they require. Least Privilege requires that these privileges must only be assigned if needed, to reduce risk of confidentiality, availability or integrity loss.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Access Control >> Roles.  View each role and verify the users and/or groups assigned to it.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

Application service account and user required privileges should be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To create a new role with specific permissions do the following:

From the vSphere Web Client go to Administration >> Access Control >> Roles. Click the green plus sign and enter a name for the role and select only the specific permissions required.  Users can then be assigned to the newly created role.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64699r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63949'
  tag rid: 'SV-78439r1_rule'
  tag stig_id: 'VCWN-06-000005'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-69877r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
