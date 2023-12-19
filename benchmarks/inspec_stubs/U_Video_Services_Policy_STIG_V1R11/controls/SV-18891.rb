control 'SV-18891' do
  title 'A VTU or conference room implemented using wireless components must be protected from external control or compromise.'
  desc 'Conference room VTC systems, and particularly large ones, can require multiple microphones, cameras, and displays along with AV control systems. These systems typically require a significant amount of wiring. This can be a problem when retrofitting a well-appointed conference room without damaging the room’s walls, ceilings, furniture, and finishes. As a result, conference room VTC systems as well as other VTC endpoint systems can utilize various wireless communication technologies to interconnect its microphones, cameras, speakers, desktop audio conferencing units, and displays to the VTC CODEC and control panels to the AV control system and CODEC. The wireless communications technologies used are 802.11, Bluetooth, standard radio (cordless telephone and wireless microphone frequencies/technology) as well as infrared. 

The use of wireless technologies to implement a conference room in a DoD facility could pose an eavesdropping vulnerability to VTC conferences and other meetings held in the facility. This could place sensitive or classified DoD information at risk. To mitigate this, all audio, video, white boarding, and data sharing communications within the conference room system must be encrypted. Furthermore, those technologies covered by the Wireless STIG and other DoD wireless policies, must be in compliance with them.'
  desc 'check', 'Interview the ISSO and validate compliance with the following requirement:

If the audio, video, white boarding, data sharing capabilities or components of a VTC system are implemented using wireless RF technologies, ensure the following:
- All information-bearing RF transmissions are encrypted to prevent eavesdropping. 
- All control-bearing RF transmissions are encrypted and/or authenticated to prevent control hijacking.
- Wireless technologies covered by the wireless STIG and other DoD wireless policies are implemented and configured in compliance with that STIG and other policies.
- Such implementations are approved by the responsible local AO in writing, and the ISSO will maintain approval documentation for inspection by IA auditors.

Note: A much more expensive mitigation to this issue would be to enclose the room in RF shielding so that the information or control bearing VTC radio signals cannot escape the facility and external control signals cannot enter the facility. This might not be practical.

Note: Wireless AV control systems or “touch panels were discussed and requirements provided earlier in this document. The earlier mentioned requirements are to be used in conjunction with this one.

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU.

Inspect the configuration of the VTC system and all wireless RF components and their associated documentation to ensure that the wireless traffic is protected. Also inspect approval documentation to ensure the responsible local AO has approved, in writing, the implementation of VTU based wireless RF components. If a VTU or conference room implemented using wireless components is not protected from external control or compromise, this is a finding.'
  desc 'fix', 'Perform the following tasks:
Purchase and install wireless RF VTC system components that can support the following:
- The encryption of all information-bearing RF transmissions to prevent eavesdropping. 
- The encrypted and/or authenticated of all control-bearing RF transmissions to prevent control hijacking.
- The configuration of wireless technologies covered by the wireless STIG and other DoD wireless policies is supported.
AND
Configure all wireless RF VTC system components to encrypt information-bearing RF transmissions to prevent eavesdropping and to encrypt and/or authenticate all control-bearing RF transmissions to prevent control hijacking.
AND
Obtain written approval from the responsible AO for the use of wireless RF components to assemble the VTC system.
AND/OR
Enclose the facility housing the VTC system in RF shielding so that the information or control bearing VTC radio signals cannot escape the facility and external control signals cannot enter the facility.
OR
Implement a hardwired VTC system.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18987r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17717'
  tag rid: 'SV-18891r2_rule'
  tag stig_id: 'RTS-VTC 4420.00'
  tag gtitle: 'RTS-VTC 4420'
  tag fix_id: 'F-17614r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1, ECWN-1'
end
