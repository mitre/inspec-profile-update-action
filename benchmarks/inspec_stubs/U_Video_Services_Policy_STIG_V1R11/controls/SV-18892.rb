control 'SV-18892' do
  title 'VTC ports and protocols cross DoD/Enclave boundaries without prior registration in the DoD Ports and Protocols Database.'
  desc 'A portion of the DoDI 8550.1 PPS policy requires registration of those PPS that cross any of the boundaries defined by the policy that are “visible to DoD-managed components”. The following PPS registration requirement applies to VTC traffic that crosses the IP based Enclave boundary to the DISN WAN or another enclave.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:

Ensure all protocols and services that cross the enclave boundary and/or any of the defined DoD boundaries (along with their associated IP ports) used by VTC systems for which he/she is responsible are registered in the DoD Ports and Protocols Database in accordance with DoDI 8550.1.

Review network diagrams, device documentation, to identify what VTC/VTU/MCU Ports/Protocols/Services are used by the VTC system.  Once these Ports/Protocols/Services have been determined and confirmed for use, verify that these same Ports/Protocols/Services are registered and approved for use in the DoD Ports and Protocols Database in accordance with DoDI 8550.1.

Note: Reference tables are provided in the STIG'
  desc 'fix', '[IP]; Perform the following tasks:
- Determine what Ports/Protocols/Services are used by the VTC system within the enclave and which cross the enclave boundary as well as what other boundaries they traverse. 
- Register all Ports/Protocols/Services are used by the VTC system in the PPS database.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18988r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17718'
  tag rid: 'SV-18892r1_rule'
  tag stig_id: 'RTS-VTC 4520.00'
  tag gtitle: 'RTS-VTC 4520.00 [IP]'
  tag fix_id: 'F-17615r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Unrestricted and undocumented traffic crossing enclave boundaries can lead to the inadvertent disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance as well as denial-of-service and the inability for the operators of the GIG to properly defend it and its interconnected enclaves.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
end
