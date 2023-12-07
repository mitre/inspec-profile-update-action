control 'SV-78489' do
  title 'The vCenter Administrator role must be secured and assigned to specific users other than a Windows Administrator.'
  desc "By default, vCenter Server grants full administrative rights to the local administrator's account, which can be accessed by domain administrators. Separation of duties dictates that full vCenter Administrative rights should be granted only to those administrators who are required to have it. This privilege should not be granted to any group whose membership is not strictly controlled. Therefore, administrative rights should be removed from the local Windows server to users who are not vCenter administrators."
  desc 'check', 'If enhanced linked mode is used then local windows authentication is not available to vCenter, this is not applicable.

Under the computer management console for windows view the local administrators group and verify only vCenter administrators have access to the vCenter server.

Other groups and users that are not vCenter administrators should be removed from the local administrators group such as Domain Admins.

If there are any groups or users present in the local administrators group of the vCenter server, this is a finding.'
  desc 'fix', 'Under the computer management console for windows view the local administrators group and remove any users or groups that are not vCenter administrators.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63999'
  tag rid: 'SV-78489r1_rule'
  tag stig_id: 'VCWN-06-000030'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69929r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
