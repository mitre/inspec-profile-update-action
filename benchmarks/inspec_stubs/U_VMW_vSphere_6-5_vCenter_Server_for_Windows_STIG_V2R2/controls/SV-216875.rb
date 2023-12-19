control 'SV-216875' do
  title 'The vCenter Server for Windows users must have the correct roles assigned.'
  desc 'Users and service accounts must only be assigned privileges they require. Least Privilege requires that these privileges must only be assigned if needed, to reduce risk of confidentiality, availability or integrity loss.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Access Control >> Roles.  

View each role and verify the users and/or groups assigned to it.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

Application service account and user required privileges should be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To update a user or groups permissions to an existing role with reduced permissions do the following:

From the vSphere Web Client go to Administration >> Access Control >> Global Permissions.  Select the user or group and click "Edit" and change the assigned role and click "OK".  If permissions are assigned on a specific object then the role must be updated where it is assigned for example at the cluster level.

To create a new role with reduced permissions do the following:

From the vSphere Web Client go to Administration >> Access Control >> Roles. Click the green plus sign and enter a name for the role and select only the specific permissions required.  Users can then be assigned to the newly created role.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18106r366339_chk'
  tag severity: 'medium'
  tag gid: 'V-216875'
  tag rid: 'SV-216875r612237_rule'
  tag stig_id: 'VCWN-65-000056'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18104r366340_fix'
  tag 'documentable'
  tag legacy: ['SV-104645', 'V-94815']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
