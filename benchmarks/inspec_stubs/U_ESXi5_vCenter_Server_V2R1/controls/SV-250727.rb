control 'SV-250727' do
  title 'Privilege re-assignment must be checked after the vCenter Server restarts.'
  desc "During a restart of vCenter Server, if the user or user group that is assigned Administrator role on the root folder could not be verified as a valid user/group during the restart, the user/group's permission as Administrator will be removed. In its place, vCenter Server defaults the Administrator role to the local Windows administrators group, to act as a new vCenter Server Administrator. This default administrative assignment must be rectified by re-establishing a legitimate vCenter Server account with an Administrator role."
  desc 'check', 'After the Windows server hosting the vCenter Server has been rebooted, a vCenter Server user or member of the user group granted the administrator role must log in and verify the role permissions remain intact. 

If the user and/or user group granted vCenter administrator role permissions cannot be verified intact, this is a finding.'
  desc 'fix', 'As a Windows Administrator, log in to the vCenter Server and restore a legitimate administrator account per site-specific user/group/role requirements.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54162r799869_chk'
  tag severity: 'medium'
  tag gid: 'V-250727'
  tag rid: 'SV-250727r799871_rule'
  tag stig_id: 'VCENTER-000005'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54116r799870_fix'
  tag 'documentable'
  tag legacy: ['V-39545', 'SV-51403']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
