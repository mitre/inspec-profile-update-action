control 'SV-250568' do
  title 'All IP-based storage traffic must be isolated using a vSwitch containing management-only port groups.'
  desc 'Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes iSCSI and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network. To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from the VMkernel management and service console network will limit unauthorized users from viewing the traffic.'
  desc 'check', 'If IP-based storage is not used, this check is not applicable.

To view the VMkernel Networking configuration, from the vSphere Client/vCenter as administrator: Select the host in the inventory pane.  On the host Configuration tab, click Networking. In the vSphere Standard Switch view, select Properties and ensure the storage port group vSwitch exclusively contains non-management port groups.

If the storage port group vSwitch does not exclusively contain management-only port groups, this is a finding.'
  desc 'fix', 'To restrict physical network access to management-only entities, modify the VMkernel Networking configuration. From the vSphere Client/vCenter as administrator: Select the host in the inventory pane. On the host Configuration tab, click Networking. In the vSphere Standard Switch view, and select Properties. Modify the storage port group vSwitch property to ensure the storage port group  vSwitch exclusively contains management-only port groups.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54003r798701_chk'
  tag severity: 'low'
  tag gid: 'V-250568'
  tag rid: 'SV-250568r798703_rule'
  tag stig_id: 'ESXI5-VMNET-000046'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53957r798702_fix'
  tag 'documentable'
  tag legacy: ['SV-51221', 'V-39363']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
