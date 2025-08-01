control 'SV-207668' do
  title 'The ESXi host must not provide root/administrator level access to CIM-based hardware monitoring tools or other third-party applications.'
  desc 'The CIM system provides an interface that enables hardware-level management from remote applications via a set of standard APIs. Create a limited-privilege, read-only service account for CIM. Grant this role to the user on the ESXi server.  Place this user in the Exception Users list.  When/where write access is required, create/enable a limited-privilege, service account and grant only the minimum required privileges.'
  desc 'check', 'The CIM system provides an interface that enables hardware-level management from remote applications via a set of standard APIs. Create a limited-privilege, read-only service account for CIM. Grant this role to the user on the ESXi server. Place this user in the Exception Users list. When/where write access is required, create/enable a limited-privilege, service account and grant only the minimum required privileges.

From the Host Client, select the ESXi host, right click and go to "Permissions". Verify the CIM account user role is limited to read only and CIM permissions.

If there is no dedicated CIM account and the root is used for CIM monitoring, this is a finding.

If write access is not required and the access level is not "read-only", this is a finding.'
  desc 'fix', 'Create a role for the CIM account.

From the Host Client, go to manage, then Security & Users. Select Roles then click Add Role. Provide a name for the new role then select Host >> Cim >> Ciminteraction and click Add.

Add a CIM user account.

From the Host Client, go to manage, then Security & Users. Select Users then click Add User. Provide a name, description, and password for the new user then click Add.

Assign the CIM account permissions to the host with the new role.

From the Host Client, select the ESXi host, right click and go to "Permissions". Click Add User and select the CIM account from the drop down list and select the new CIM role from the drop down list and click Add User.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7923r364403_chk'
  tag severity: 'medium'
  tag gid: 'V-207668'
  tag rid: 'SV-207668r388482_rule'
  tag stig_id: 'ESXI-65-000070'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7923r364404_fix'
  tag 'documentable'
  tag legacy: ['SV-104303', 'V-94349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
