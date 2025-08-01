control 'SV-18890' do
  title 'A VTU endpoint does not have the wireless LAN capability disabled.'
  desc 'The proper mitigation for the vulnerabilities discussed above is to disable the wireless capability available or included in a VTC endpoint. Typically, one would expect a configuration setting that says something like “Disable Wireless” that would disable any onboard wireless capability whether integrated or reliant on a plug-in card. The Wireless STIG in WIR0167 requires all wireless LAN NICs to be turned-off by default after system boot-up or whenever a wireless network connection is not required. Additionally WIR0130 requires that the NIC have the capability to disable ad hoc connectivity. While these requirements are addressed toward PCs and PEDs, they are applicable to VTC endpoints.  Support for these requirements does not seem to be available with at least some VTC endpoint’s PCMCIA wireless LAN card implementations. It is conceivable that a WLAN card could be inserted into the PCMCIA slot and activated with basic default settings and no security. To prevent this, the VTU’s  PCMCIA slot must be physically blocked, making it difficult to insert a WLAN card.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:
     
Ensure wireless capability is configured as “disabled”.
     
Note: In the event such a setting is not available for a PCMCIA WLAN card. This finding can be reduced to a CAT III if the PCMCIA slot is fitted with a hard to remove device that prevents the insertion of a card into the slot.  
     
If the VTU supports wireless LAN connectivity and it is not needed, verify that it is it is disabled. In the event the wireless capability is supported by inserting a WLAN card onto a PCMCIA slot, verify that the wireless capability remains disabled when the card is inserted. In the event such a setting is not available for a PCMCIA WLAN card verify that the PCMCIA slot is fitted with a hard to remove device that prevents the insertion of a card into the slot.  
     
Note: It is recognized that there is no mitigation for or configuration setting that would prevent the connection of an external wireless LAN adaptor via the wired LAN connection. This however would not permit both the wired and wireless LAN capabilities of the VTU to be active at the same time.'
  desc 'fix', '[IP];  Perform the following tasks:
Configure the VTU to disable wireless LAN capabilities whether an internal wireless adaptor or a WLAN card plugged into a PCMCIA slot is used.
OR
Physically prevent the ability to insert a WLAN card into a PCMCIA slot.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18986r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17716'
  tag rid: 'SV-18890r1_rule'
  tag stig_id: 'RTS-VTC 4360.00'
  tag gtitle: 'RTS-VTC 4360.00 [IP]'
  tag fix_id: 'F-17613r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'In the event a configuration setting is not available for a PCMCIA WLAN card that will disable it when one is plugged in, this finding can be reduced to a CAT III if the PCMCIA slot is fitted with a hard to remove device that prevents the insertion of a card into the slot.'
  tag potential_impacts: 'Unregulated and improperly configured wireless adapters have the potential to provide backdoor connectivity, which ultimately can lead to the inadvertent disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
end
