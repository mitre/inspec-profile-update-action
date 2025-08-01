control 'SV-216852' do
  title 'The vCenter Server for Windows Administrator role must be secured and assigned to specific users other than a Windows Administrator.'
  desc "By default, vCenter Server grants full administrative rights to the local administrator's account, which can be accessed by domain administrators. Separation of duties dictates that full vCenter Administrative rights should be granted only to those administrators who are required to have it. This privilege should not be granted to any group whose membership is not strictly controlled. Therefore, administrative rights should be removed from the local Windows server to users who are not vCenter administrators."
  desc 'check', 'If enhanced linked mode is used then local windows authentication is not available to vCenter, this is not applicable.

Under the computer management console for Windows, view the local administrators group and verify only vCenter administrators have access to the vCenter server.

Other groups and users that are not vCenter administrators should be removed from the local administrators group, such as Domain Admins.

If there are any unauthorized groups or users present in the local administrators group of the vCenter server, this is a finding.'
  desc 'fix', 'Under the computer management console for windows view the local administrators group and remove any users or groups that do not fit the criteria defined in the check content.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18083r766915_chk'
  tag severity: 'medium'
  tag gid: 'V-216852'
  tag rid: 'SV-216852r766916_rule'
  tag stig_id: 'VCWN-65-000030'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18081r366271_fix'
  tag 'documentable'
  tag legacy: ['SV-104599', 'V-94769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
