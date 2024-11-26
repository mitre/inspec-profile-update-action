control 'SV-55753' do
  title 'An IP-based VTC system implementing a single set of input/output devices (cameras, microphones, speakers, control system), an A/V switcher, and multiple CODECs connected to multiple IP networks having different classification levels must provide automatic mutually exclusive power control for the CODECs or their network connections such that only one CODEC is powered on or one CODEC is connected to any network at any given time.'
  desc 'If a VTC system is implemented using multiple CODECs, each connected to a network having a different classification level, along with an A/V switcher, a potential path exists through the CODECs and A/V switcher that could permit classified information to be exposed/released from one classified network to a network having a lower classification. Minimally powering off the CODEC will provide a level of isolation that will prevent active passage of data. The above solution could still provide an electrical leakage path between the networks whereby classified information could leak onto another network. 
To improve on the electrical isolation between networks and as an alternative to powering off the CODECs, an optical link using fiber optic to Ethernet media adaptors/converters/modems between the CODEC and each of the networks it serves could be implemented. In this case, the fiber optic media adaptors would be powered in a mutually exclusive manner. 
Mutually exclusive power means that only one CODEC or fiber optic adaptor can be powered at a time. Turning on one CODEC or fiber optic adaptor turns off power for all others.'
  desc 'check', 'Review the VTC system architecture to determine the method of network isolation used. 
Verify that only one CODEC or fiber optic media adaptor can be turned on at a time by attempting to turn on more than one CODEC concurrently. If more than one CODEC operates, this is a finding.'
  desc 'fix', 'Obtain and implement a power control system that can support automatic mutually exclusive power control.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49181r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43024'
  tag rid: 'SV-55753r1_rule'
  tag stig_id: 'RTS-VTC 7180'
  tag gtitle: 'RTS-VTC 7180 [IP]'
  tag fix_id: 'F-48608r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCSP-1'
end
