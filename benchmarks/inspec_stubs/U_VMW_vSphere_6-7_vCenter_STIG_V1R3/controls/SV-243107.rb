control 'SV-243107' do
  title 'The vCenter Server users must have the correct roles assigned.'
  desc 'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc 'check', 'From the vSphere Client, go to Administration >> Access Control >> Roles. 

View each role and verify the users and/or groups assigned to it.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

Application service account and user required privileges should be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To create a new role with specific permissions:

From the vSphere Client, go to Administration >> Access Control >> Roles. 

Click the plus sign, enter a name for the role, and select only the specific permissions required. 

Users can then be assigned to the newly created role.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46382r719562_chk'
  tag severity: 'medium'
  tag gid: 'V-243107'
  tag rid: 'SV-243107r719564_rule'
  tag stig_id: 'VCTR-67-000051'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-46339r719563_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
