control 'SV-250548' do
  title 'All IP-based storage traffic must be isolated to a management-only network using a dedicated, physical network adaptor.'
  desc 'Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes iSCSI and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network. To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from the VMkernel management and service console network will limit unauthorized users from viewing the traffic.'
  desc 'check', 'If IP-based storage is not used, this check is not applicable.

To view the VMkernel Networking configuration, from the vSphere Client/vCenter as administrator: Select the host in the inventory pane.  On the host Configuration tab, click Networking. In the vSphere Standard Switch view, select Properties and ensure at least one physical network adaptor is dedicated to a management-only network. 

If at least one physical network adaptor is not dedicated to a management-only network, this is a finding.'
  desc 'fix', 'Restrict physical network access to management-only entities. To modify VMkernel Networking configuration, from the vSphere Client/vCenter as administrator: Select the host in the inventory pane. On the host Configuration tab, click Networking. In the vSphere Standard Switch view, select Properties and modify the properties to enforce the dedication of at least one physical network adaptor  to management-only.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53983r798641_chk'
  tag severity: 'low'
  tag gid: 'V-250548'
  tag rid: 'SV-250548r798643_rule'
  tag stig_id: 'ESXI5-VMNET-000006'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53937r798642_fix'
  tag 'documentable'
  tag legacy: ['SV-51219', 'V-39361']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
