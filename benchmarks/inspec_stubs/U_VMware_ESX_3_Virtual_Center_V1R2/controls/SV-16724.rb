control 'SV-16724' do
  title 'VMotion virtual switches are not configured with a dedicated physical network adapter'
  desc 'The security issue with VMotion migrations is that the encapsulated files are transmitted in plaintext. Plaintext provides no confidentiality, and anyone with the proper access may view these files. To mitigate this risk, a dedicated VLAN will be used for all VMotion migrations. Configuring a dedicated VLAN requires that VMotion virtual switches are configured with one physical network adapter on a separate VLAN. This will ensure that VMotion traffic is separate from production traffic. The preferred method to transfer these encapsulated files is to encrypt them with a FIPS 140-2 encryption algorithm.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the server from the inventory panel.
    The hardware configuration page for this server appears.
2. Click the Configuration tab, and click Networking.  
3. Examine the virtual switches and their respective VLAN IDs.  A separate and dedicated physical network adapter should be configured for VMotion migrations to and from VMFS volumes. If there is no dedicated physical network adapter for these transfers, this is a finding. To illustrate a dedicated physical network adapter the figure below shows the service console configured on a separate physical network adapter.  

Caveat: This check is Not Applicable if all the network adapters are configured as a NIC Team.'
  desc 'fix', 'Configure a dedicated physical network adapter for all VMotion virtual switches.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-15971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15785'
  tag rid: 'SV-16724r1_rule'
  tag stig_id: 'ESX0030'
  tag gtitle: 'No dedicated NIC for Vmotion vswitch'
  tag fix_id: 'F-15726r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
