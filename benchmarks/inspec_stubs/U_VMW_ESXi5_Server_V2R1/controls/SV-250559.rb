control 'SV-250559' do
  title 'The non-negotiate option must be configured for trunk links between external physical switches and virtual switches in VST mode.'
  desc 'In order to communicate with virtual switches in VST mode, external switch ports must be configured as trunk ports. VST mode does not support Dynamic Trunking Protocol (DTP), so the trunk must be static and unconditional. The auto or desirable physical switch settings do not work with the ESXi Server because the physical switch communicates with the ESXi Server using DTP. The non-negotiate and on options unconditionally enable VLAN trunking on the physical switch and create a VLAN trunk link between the ESXi Server and the physical switch. The difference between non-negotiate and on options is that on mode still sends out DTP frames, whereas the non-negotiate option does not.  The non-negotiate option should be used for all VLAN trunks, to minimize unnecessary network traffic for virtual switches in VST mode.'
  desc 'check', 'Note that this check refers to an entity outside the physical scope of the ESXi server system. The configuration of external switch ports as trunk ports must be documented. Virtual Switch Tagging (VST) mode does not support Dynamic Trunking Protocol (DTP), so the trunk must be static and unconditional. Inspect the documentation and verify that the documentation is correct and updated on an organization defined frequency and/or whenever modifications are made to either ESXi hosts or the upstream external switch ports.

If DTP is enabled on the physical switch ports connected to the ESXi Host, this is a finding.'
  desc 'fix', 'Note that this check refers to an entity outside the physical scope of the ESXi server system. Document the configuration of external switch ports as trunk ports. Log in to the vendor-specific physical switch and disable DTP on the physical switch ports connected to the ESXi Host. Update the documentation on an organization defined frequency or whenever modifications are made to either ESXi hosts or the upstream external switch ports.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53994r798674_chk'
  tag severity: 'medium'
  tag gid: 'V-250559'
  tag rid: 'SV-250559r798676_rule'
  tag stig_id: 'ESXI5-VMNET-000017'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53948r798675_fix'
  tag 'documentable'
  tag legacy: ['V-39374', 'SV-51232']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
