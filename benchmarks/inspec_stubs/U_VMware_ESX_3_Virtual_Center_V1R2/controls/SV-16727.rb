control 'SV-16727' do
  title 'iSCSI VLAN or network segment is not configured for iSCSI traffic.'
  desc 'Virtual machines may share virtual switches and VLANs with the iSCSI configuration. This type of configuration may expose iSCSI traffic to unauthorized virtual machine users. To restrict unauthorized users from viewing the iSCSI traffic, the iSCSI network should be logically separated from the production traffic. Configuring the iSCSI adapters on separate VLANs or network segments from the VMkernel and service console will limit unauthorized users from viewing the traffic.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the server from the inventory panel.
    The hardware configuration page for this server appears.
2. Click the Configuration tab, and click Networking.  
3. Examine the virtual switches and their respective VLAN IDs.  A separate and dedicated VLAN should be configured for all iSCSI connections. If there is no dedicated VLAN for iSCSI, this is a finding.'
  desc 'fix', 'Configure a dedicated VLAN or network segment for iSCSI connections.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-15975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15788'
  tag rid: 'SV-16727r1_rule'
  tag stig_id: 'ESX0060'
  tag gtitle: 'iSCSI VLAN is not configured for iSCSI traffic.'
  tag fix_id: 'F-15730r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
