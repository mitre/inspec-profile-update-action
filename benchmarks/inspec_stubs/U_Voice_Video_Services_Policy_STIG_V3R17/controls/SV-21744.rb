control 'SV-21744' do
  title 'The required dual homed DISN Core or NIPRNet access circuits DO NOT follow geographically diverse paths from the CER(s) along the entire route to the geographically diverse SDNs.'
  desc 'In previous requirements we discussed the need for redundant DISN Core access circuits between the enclave and the DISN SDNs. Another method for providing the greatest reliability and availability for DISN services is to provide redundancy in the network pathways between the customer site and the redundant DISN SDNs. The DISN core network is designed to be highly reliable and available in support of the DoD mission, the most vulnerable part of the network is the access circuit from the enclave to the core and the path it takes from the SDN to the customer’s site. Therefore redundant access circuits should be provisioned. Physical pathways for communications network access circuits are vulnerable to physical disruption from a variety of threats, both natural and man made. These threats range from storm damage (falling trees, floods, to being damaged or dug up by “the big yellow fiber-finder” (backhoe); to rampaging vehicles attacking utility poles; to malicious acts including war and terrorism. To overcome the physical threat, the redundant circuits should follow geographically diverse paths.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure the required dual homed DISN Core or NIPRNet access circuits follow geographically diverse paths from the CER(s) along the entire route to the geographically diverse SDNs. Each circuit will use different facilities such as cables, demarks, and digital cross connects in geographically diverse locations. 
NOTE: Geographic and facilities diversity will be maintained on-site and off-site.

This is a finding in the event the required dual-homed circuits follow the same path or are close enough to be damaged by a single event.

NOTE: The paths taken by the access circuits must remain significantly separate for their entire length such that a single point of failure is not created.'
  desc 'fix', 'Ensure dual homed DISN Core or NIPRNet access circuits follow geographically diverse paths from the CER(s) along the entire route to the geographically diverse SDNs. 

Ensure each circuit uses different facilities such as cables, demarks, and digital cross connects in geographically diverse locations. 

Ensure geographic and facilities is maintained on-site and off-site.

Ensure the paths taken by the access circuits remain significantly separate along their entire length such that a single point of failure is not created.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23883r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19603'
  tag rid: 'SV-21744r1_rule'
  tag stig_id: 'VVoIP 6145 (DISN-IPVS)'
  tag gtitle: 'Deficient Design: Dual Homed ckts; Diverse Paths'
  tag fix_id: 'F-20302r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Reduced availability and the inability to complete a C2 call'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCBP-1, ECSC-1'
end
