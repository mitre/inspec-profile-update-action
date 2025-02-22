control 'SV-216870' do
  title 'The vCenter Server for Windows users must have the correct roles assigned.'
  desc 'Users and service accounts must only be assigned privileges they require. Least Privilege requires that these privileges must only be assigned if needed, to reduce risk of confidentiality, availability or integrity loss.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Access Control >> Roles.  

View each role and verify the users and/or groups assigned to it.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

Application service account and user required privileges should be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To create a new role with specific permissions do the following:

From the vSphere Web Client go to Administration >> Access Control >> Roles. Click the green plus sign and enter a name for the role and select only the specific permissions required.  Users can then be assigned to the newly created role.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18101r366324_chk'
  tag severity: 'medium'
  tag gid: 'V-216870'
  tag rid: 'SV-216870r612237_rule'
  tag stig_id: 'VCWN-65-000051'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-18099r366325_fix'
  tag 'documentable'
  tag legacy: ['V-94805', 'SV-104635']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
