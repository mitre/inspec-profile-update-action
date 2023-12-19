control 'SV-216848' do
  title 'The vCenter Server for Windows must check the privilege re-assignment after restarts.'
  desc 'Check for privilege reassignment when you restart vCenter Server. If the user or user group that is assigned the Administrator role on the root folder cannot be verified as a valid user or group during a restart, the role is removed from that user or group. In its place, vCenter Server grants the Administrator role to the vCenter Single Sign-On account administrator@vsphere.local. This account can then act as the administrator.

Reestablish a named administrator account and assign the Administrator role to that account to avoid using the anonymous administrator@vsphere.local account.'
  desc 'check', 'After the Windows server hosting the vCenter Server has been rebooted, a vCenter Server user or member of the user group granted the administrator role must log in and verify the role permissions remain intact. 

If the user and/or user group granted vCenter administrator role permissions cannot be verified as intact, this is a finding.'
  desc 'fix', 'As the SSO Administrator, log in to the vCenter Server and restore a legitimate administrator account per site-specific user/group/role requirements.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18079r366258_chk'
  tag severity: 'medium'
  tag gid: 'V-216848'
  tag rid: 'SV-216848r612237_rule'
  tag stig_id: 'VCWN-65-000026'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18077r366259_fix'
  tag 'documentable'
  tag legacy: ['SV-104675', 'V-94845']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
