control 'SV-18888' do
  title 'VTC endpoint connectivity is established via an unapproved DoD Wireless LAN infrastructure'
  desc 'In the event wireless LAN connectivity is to be used for VTC endpoints, it must be implemented via an established and approved wireless LAN infrastructure which is configured, along with its connected devices, in compliance with the Wireless STIG. Key requirements include WiFi and WPA2 certification of the VTC wireless LAN Network Interface Card (NIC) and FIPS 140-2 certification of the wireless encryption module.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:

Ensure VTC endpoint connectivity is established via an approved DoD wireless LAN infrastructure. Furthermore, ensure both the LAN and VTC endpoint are configured and operated in compliance with the Wireless STIG. 

Note: During APL testing, this is a finding in the event the VTU cannot come into compliance with the applicable requirements in the Wireless STIG. 

Inspect VTU configuration to verify with that if wireless is not required it is disabled.  If wireless connectivity is required verify/inspect that the wireless functionality is configured and operating in accordance with the Wireless STIG.'
  desc 'fix', '[IP]; Perform the following tasks:
If wireless LAN connectivity is required, configure the wireless LAN capabilities of a VTU using the applicable requirements in the Wireless STIG.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18984r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17714'
  tag rid: 'SV-18888r1_rule'
  tag stig_id: 'RTS-VTC 4220.00'
  tag gtitle: 'RTS-VTC 4220.00 [IP]'
  tag fix_id: 'F-17611r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Unregulated and improperly configured wireless adapters have the potential to provide backdoor connectivity, which ultimately can lead to the inadvertent disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
end
