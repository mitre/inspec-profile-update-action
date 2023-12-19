control 'SV-78479' do
  title 'Privilege re-assignment must be checked after the vCenter Server restarts.'
  desc 'Check for privilege reassignment when you restart vCenter Server. If the user or user group that is assigned the Administrator role on the root folder cannot be verified as a valid user or group during a restart, the role is removed from that user or group. In its place, vCenter Server grants the Administrator role to the vCenter Single Sign-On account administrator@vsphere.local. This account can then act as the administrator.

Reestablish a named administrator account and assign the Administrator role to that account to avoid using the anonymous administrator@vsphere.local account.'
  desc 'check', 'After the Windows server hosting the vCenter Server has been rebooted, a vCenter Server user or member of the user group granted the administrator role must log in and verify the role permissions remain intact. 

If the user and/or user group granted vCenter administrator role permissions cannot be verified intact, this is a finding.'
  desc 'fix', 'As the SSO Administrator, log in to the vCenter Server and restore a legitimate administrator account per site-specific user/group/role requirements.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63989'
  tag rid: 'SV-78479r1_rule'
  tag stig_id: 'VCWN-06-000026'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69919r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
