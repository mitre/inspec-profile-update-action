control 'SV-16725' do
  title 'There is no dedicated VLAN or network segment configured for virtual disk file transfers.'
  desc 'The transfer of virtual disk files and VMotion migrations to and from VMFS volumes is sent in plaintext. This type of traffic provides no confidentiality for the data. Due to this vulnerability, at a minimum, virtual disk file transfers and VMotion migrations will be sent over a dedicated VLAN.  The preferred method for these transfers is to encrypt this traffic with a FIPS 140-2 encryption algorithm.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
2. Click the Configuration tab, and click Networking.  
3. Examine the virtual switches and their respective VLAN IDs. A separate and dedicated VLAN  should be configured for virtual disk transfers and VMotion migrations to and from VMFS volumes. The administrative VLAN or Out of Band VLAN is acceptable for compliance.  If there is no dedicated VLAN for these transfers, this is a finding.'
  desc 'fix', 'Implement a dedicated VLAN for all virtual disk file transfers to and from VMFS volumes.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-15972r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15786'
  tag rid: 'SV-16725r1_rule'
  tag stig_id: 'ESX0040'
  tag gtitle: 'No dedicated VLAN for virtual disk transfers.'
  tag fix_id: 'F-15727r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
