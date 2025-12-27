control 'SV-243076' do
  title 'The vCenter Server users must have the correct roles assigned.'
  desc 'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc 'check', 'From the vSphere Client, go to Administration >> Access Control >> Roles. 

View each role and verify the users and/or groups assigned to it.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

Application service account and user required privileges should be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', %q(To update a user's or group's permissions to an existing role with reduced permissions:

From the vSphere Client, go to Administration >> Access Control >> Global Permissions. 

Select the user or group, click "Edit", change the assigned role, and click "OK". 

If permissions are assigned on a specific object, the role must be updated where it is assigned (for example, at the cluster level).

To create a new role with reduced permissions:

From the vSphere Client, go to Administration >> Access Control >> Roles. 

Click the green plus sign, enter a name for the role, and select only the specific permissions required.

Users can then be assigned to the newly created role.)
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46351r719469_chk'
  tag severity: 'medium'
  tag gid: 'V-243076'
  tag rid: 'SV-243076r879631_rule'
  tag stig_id: 'VCTR-67-000005'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-46308r719470_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
