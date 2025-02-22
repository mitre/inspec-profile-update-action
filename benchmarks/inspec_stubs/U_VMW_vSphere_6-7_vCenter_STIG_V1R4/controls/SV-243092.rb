control 'SV-243092' do
  title 'The vCenter Server must check the privilege reassignment after restarts.'
  desc 'Check for privilege reassignment when restarting vCenter Server. If the user or user group that is assigned the Administrator role on the root folder cannot be verified as a valid user or group during a restart, the role is removed from that user or group. In its place, vCenter Server grants the Administrator role to the vCenter Single Sign-On account administrator@vsphere.local. This account can then act as the Administrator.

Reestablish a named Administrator account and assign the Administrator role to that account to avoid using the anonymous administrator@vsphere.local account.'
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

After the Windows server hosting the vCenter Server has been rebooted, a vCenter Server user or member of the user group granted the Administrator role must log in and verify the role permissions remain intact. 

If the user and/or user group granted vCenter Administrator role permissions cannot be verified as intact, this is a finding.'
  desc 'fix', 'As the SSO Administrator, log in to the vCenter Server and restore a legitimate Administrator account per site-specific user/group/role requirements.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46367r719517_chk'
  tag severity: 'medium'
  tag gid: 'V-243092'
  tag rid: 'SV-243092r879887_rule'
  tag stig_id: 'VCTR-67-000026'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46324r719518_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
