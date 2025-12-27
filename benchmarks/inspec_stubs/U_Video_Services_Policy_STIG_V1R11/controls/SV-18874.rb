control 'SV-18874' do
  title 'CODEC control / configuration messages received via the local Application Programmers Interface (API) are not encrypted or authenticated.'
  desc 'The commands passed between the “touch panel” and CODEC are typically in a human readable clear text format. While older touch panels required a physical and direct connection to the EIA-232 serial connection on the CODEC, newer models are being developed to make use of Ethernet networks and associated IP protocols. Wireless models are also becoming available using wireless networking technologies. Sending clear text commands across these types of connections is an issue because it places the CODEC at risk of hijack i.e., being controlled by an entity other than the authorized touch panel in the conference room.  Due to these issues, if the touch panel is implemented using a networking technology, the API commands must be encrypted in transit and the CODEC must authenticate the source of the commands.'
  desc 'check', '[IP][ISDN]; Validate compliance with the following requirement:

Ensure control command communications between a CODEC and an audio visual control panel (touch panel), implemented using a wired or wireless networking technology, or is via a wired network (i.e., LAN), is encrypted and the CODEC authenticates the source of the commands. 
     
Note: This finding can be reduced to a CAT III (as opposed to not-a finding) for direct connections using the Ethernet connection on the CODEC. This is because, in this case, direct connection is only a partial mitigation since there is the potential that the VTU could still be connected to a LAN 
     
Note: This is not a finding for direct connections using the EIA-232 serial connection on the CODEC.

Determine if the API connection between a CODEC and its AV control panel is via wired or wireless networking technology or a LAN. This is a finding if the control panel does not encrypt its commands and the CODEC does not authenticate the source of the commands. Have the SA demonstrate or Inspect the CODEC’s configuration settings regarding the encryption and authentication methods for the API communications with the AV control panel.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Purchase and implement VTC CODECs and AV control panels that support the encryption and authentication of API messages from the AV control panel. 
AND 
Configure VTC CODEC to only accept authenticated and encrypted API messages from the AV control panel. 
AND
Configure the AV control panel to encrypt its control messages and to include authentication information for each message such that the CODEC can authenticate the source of the message before acting upon it.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18970r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17700'
  tag rid: 'SV-18874r2_rule'
  tag stig_id: 'RTS-VTC 2840.00'
  tag gtitle: 'RTS-VTC 2840.00 [IP][ISDN]'
  tag fix_id: 'F-17597r1_fix'
  tag 'documentable'
  tag mitigations: 'RTS-VTC 2840.00'
  tag severity_override_guidance: 'This finding can be reduced to a CAT III (as opposed to not-a finding) for direct connections using the Ethernet connection on the CODEC. This is because, in this case, direct connection is only a partial mitigation since there is the potential that the VTU could still be connected to a LAN.  

This is not a finding for direct connections using the EIA-232 serial connection on the CODEC.'
  tag potential_impacts: 'Unencrypted and unauthorized access to the CODEC via API Ethernet or wireless connection by unauthorized individuals, could possibly lead to the disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag mitigation_control: 'Use the direct connect method using the EIA-232 serial connection between the CODEC and the AV control panel'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
