control 'SV-250549' do
  title 'Only authorized administrators must have access to virtual networking components.'
  desc "This control mitigates the risk of misconfiguration, whether accidental or malicious, and enforces key security concepts of separation of duties and least privilege. It is important to leverage the role-based access controls within vSphere to ensure that only authorized administrators have access to the different virtual networking components. For example, VM administrators should have access only to port groups in which their VMs reside. Network administrators should have permissions to all virtual networking components but not have access to VMs. These controls will depend very much on the organization's policy on separation of duties, least privilege, and the responsibilities of the administrators within the organization."
  desc 'check', 'vSphere permissions to specific port groups must be granted only to individuals who need it. From the vSphere Client/vCenter as a user with full Administrator Role rights to the Inventory object to be checked:
Select "[Inventory Object]>> Permissions". Verify that users assigned to the selected Inventory object have the appropriate role.

If any user assigned to the selected Inventory object have an inappropriate role, this is a finding.'
  desc 'fix', 'vSphere permissions to specific port groups must be granted only to individuals who need it. From the vSphere Client/vCenter as a user with full Administrator Role rights to the Inventory object to be checked:
(1) Select "[Inventory Object]>> Permissions". Assign users with the appropriate Role to the all Inventory object(s).'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53984r798644_chk'
  tag severity: 'low'
  tag gid: 'V-250549'
  tag rid: 'SV-250549r798646_rule'
  tag stig_id: 'ESXI5-VMNET-000007'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53938r798645_fix'
  tag 'documentable'
  tag legacy: ['V-39364', 'SV-51222']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
