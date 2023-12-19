control 'SV-77799' do
  title 'The system must not provide root/administrator level access to CIM-based hardware monitoring tools or other third-party applications.'
  desc 'The CIM system provides an interface that enables hardware-level management from remote applications via a set of standard APIs. Create a limited-privilege, read-only service account for CIM. Grant this role to the user on the ESXi server.  Place this user in the Exception Users list.  When/where write access is required, create/enable a limited-privilege, service account and grant only the minimum required privileges.'
  desc 'check', 'If the CIM account does not exist, this check is not applicable.

If write access is required, this check is not applicable.

From the vSphere client, select the ESXi host, and go to "Permissions". Select the CIM account user, then right-click and select properties to verify read-only access.

If write access is not required and the access level is not "read-only", this is a finding.'
  desc 'fix', 'From the vSphere client, select the ESXi host; go to "Local Users and Groups". Create a limited-privileged, read-only service account for CIM. Place the CIM account into the "root" group. Select Users and right-click in the user screen. Select "Add", then Add a new user. If write access is required only grant the minimum required privileges. CIM accounts should be limited to the "Host >> Config >> System Management" and "Host >> CIM >> CIMInteraction" privileges.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64043r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63309'
  tag rid: 'SV-77799r1_rule'
  tag stig_id: 'ESXI-06-000070'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
