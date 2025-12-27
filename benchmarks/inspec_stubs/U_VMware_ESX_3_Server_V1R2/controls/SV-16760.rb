control 'SV-16760' do
  title 'The non-negotiate option is not configured for trunk links between external physical switches and virtual switches in VST mode.'
  desc 'In order to communicate with virtual switches in VST mode, external switch ports must be configured as trunk ports. VST mode does not support Dynamic Trunking Protocol (DTP), so the trunk must be static and unconditional. The auto or desirable physical switch settings do not work with the ESX Server because the physical switch expects the ESX Server to communicate using DTP. The non-negotiate and on options enable VLAN trunking on the physical switch unconditionally and create a VLAN trunk link between the ESX Server and the physical switch. The difference between non-negotiate and on options is that on mode still sends out DTP frames, and the non-negotiate option does not. The non-negotiate option should be used for all VLAN trunks to minimize unnecessary network traffic for virtual switches in VST mode.'
  desc 'check', 'Request of copy of the external switch configuration that the ESX Server has trunk links configured. Work with the network reviewer and system administrator to verify the non-negotiate option is set.  

Cisco CATOS switch:

CATOS Console> (enable) set trunk <port number> nonnegotiate dot1q

Cisco IOS switch:

IOS Console# switchport trunk nonnegotiate

If the non-negotiate option is not set, this is a finding.'
  desc 'fix', 'Configure the non-negotiate option for trunks connected to external physical switches.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15821'
  tag rid: 'SV-16760r1_rule'
  tag stig_id: 'ESX0300'
  tag gtitle: 'Non-negotiate not set for virtual switches in VST.'
  tag fix_id: 'F-15773r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
