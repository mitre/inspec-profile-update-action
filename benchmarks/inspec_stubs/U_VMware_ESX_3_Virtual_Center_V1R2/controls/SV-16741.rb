control 'SV-16741' do
  title 'The service console and virtual machines are not on dedicated VLANs or network segments.'
  desc 'Virtual machine traffic destined for a physical network should always be placed on a separate physical adapter from service console traffic. It is appropriate to use as many additional physical adapters as are necessary to support virtual machine networks. It may be sufficient to place the service console and virtual machine networks on separate VLANs connected to the same adapter, but connecting them to separate physical networks provides better isolation and more configuration control than is available using VLANs alone. The ESX Server VLAN implementation provides adequate network isolation, but it is possible that traffic could be misdirected due to improper configuration or security vulnerabilities in external networking hardware. It is safer to keep them physically separate.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
2. Click the Configuration tab, and click Networking.  
3. Examine the virtual switches and their respective VLAN IDs. A separate VLAN ID should be configured for the service console and virtual machine traffic. If the virtual machines and service console are on the same VLAN ID, this is a finding.'
  desc 'fix', 'Configure separate VLANs or network segments for the service console and virtual machine traffic.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16019r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15802'
  tag rid: 'SV-16741r1_rule'
  tag stig_id: 'ESX0130'
  tag gtitle: 'Virtual machines are not on dedicated VLAN.'
  tag fix_id: 'F-15745r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
