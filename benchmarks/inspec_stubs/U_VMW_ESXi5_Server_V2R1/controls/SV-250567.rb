control 'SV-250567' do
  title 'All IP-based storage traffic must be isolated to a management-only network using a dedicated, management-only vSwitch.'
  desc 'Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes iSCSI and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network. To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from the VMkernel management and service console network will limit unauthorized users from viewing the traffic.'
  desc 'check', 'If IP-based storage is not used, this check is not applicable.

To view the VMkernel Networking configuration, from the vSphere Client/vCenter as administrator: Select the host in the inventory pane.  On the host Configuration tab, click Networking. In the vSphere Standard Switch view, select Properties and ensure the storage port group is on a management-only vSwitch. 

If the storage port group is not on a management-only vSwitch, this is a finding.'
  desc 'fix', 'To restrict physical network access to management-only entities, modify the VMkernel Networking configuration. From the vSphere Client/vCenter as administrator: Select the host in the inventory pane. On the host Configuration tab, click Networking. In the vSphere Standard Switch view, select Properties. Modify the storage port group property to ensure the storage port group  is located on a management-only vSwitch.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54002r798698_chk'
  tag severity: 'low'
  tag gid: 'V-250567'
  tag rid: 'SV-250567r798700_rule'
  tag stig_id: 'ESXI5-VMNET-000036'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53956r798699_fix'
  tag 'documentable'
  tag legacy: ['V-39362', 'SV-51220']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
