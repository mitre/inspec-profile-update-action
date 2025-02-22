control 'SV-17107' do
  title 'Deficient PPS registration of those PPSs used by a Voice/Video/UC system to include its core infrastructure devices and hardware based or PC application based endpoints.'
  desc 'DoDI 8550.1 Ports, Protocols, and Services Management (PPSM) is the DoD’s policy on IP Ports, Protocols, and Services (PPS). It controls the PPS that are permitted or approved to cross DoD network boundaries as well as mitigations for vulnerabilities inherent in the approved PPSs. Standard well known and registered IP ports and associated protocols and services are assessed for vulnerabilities and threats to the entire Global Information Grid (GIG) which includes the DISN backbone networks. The results are published in a Vulnerability Assessment (VA) report. Each port and protocol is given a rating of green, yellow, orange, or red associated with each of the 16 defined boundary types. Green means the protocol is relatively secure and is approved to cross the associated boundary without restrictions. Yellow means the protocol has issues that can be mitigated and it can be used if the required mitigations are used as noted in the VA. Red means that the protocol issues cannot be mitigated, is not secure, or approved, and in fact is banned when crossing that boundary. A new category is Orange which is the same as red except that the protocol is in use and cannot be removed from the network. It recognizes that the protocol exists on the network and is necessary but also mandates that new systems and applications must not be developed using this protocol whether it crosses a boundary or not. Some red and orange protocols have mitigations listed in their VA that must be used if the protocol is used during its remaining life. The information regarding the assessed ports and protocols and the defined boundaries is published in the PPS Assurance Categories Assignment List (CAL). See the Enclave and Network Infrastructure STIGS, the 8550.1, and the latest PPS CAL for a more complete discussion of this DoD program and policy. The PPSM information is available on the IASE and DKO/DoD IA Portal web sites. A portion of the DoDI 8550.1 PPS policy requires registration of those PPS that cross any of the boundaries defined by the policy that are “visible to DoD-managed components”. The following PPS registration requirement applies to all PPSs used by a Voice/Video/UC system to include the core infrastructure devices and its hardware based or PC application based endpoints whether or not a PPS crosses the IP based Enclave boundary to the DISN WAN or another enclave. The PPSM PMO is requiring internal PPSs to be registered in case they find their way to the DISN WAN.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement: 

Ensure all IP Ports, Protocols, and Services (PPSs) used by a Voice/Video/UC system to include its core infrastructure devices and hardware-based or PC application-based endpoints are registered in the DoD Ports and Protocols Database in accordance with DoDI 8550.1. This applies to PPSs that remain within the enclave (“local PPS”) and those that cross the enclave boundary and/or any of the defined DoD boundaries.

Determine the PPS used by all Voice/Video/UC system devices and endpoints (to include PC based endpoints) used at the site within the enclave and those that cross a boundary as well as the boundaries they cross where the network is exposed to them. Inspect the system documentation and if necessary contact the vendor. If necessary, use a sniffer to detect the protocols used. This would require operating all system functions or sniffing during a period of time when all functions are accessed. 

Inspect PPS registrations with regard to PPS used. 

This is a finding if all IP ports and protocols used by the Voice/Video/UC system to include its core infrastructure devices and its hardware based or PC application based endpoints are NOT registered in the DoD Ports and Protocols Database in accordance with DoDI 8550.1.'
  desc 'fix', 'Ensure all IP Ports, Protocols, and Services (PPSs) used by a Voice/Video/UC system to include its core infrastructure devices and its hardware-based or PC application-based endpoints are registered in the DoD Ports and Protocols Database in accordance with DoDI 8550.1. This applies to PPSs that remain within the enclave (“local PPS”) and those that cross the enclave boundary and/or any of the defined DoD boundaries.

Properly register all IP ports and protocols used by the Voice/Video/UC system to include its core infrastructure devices and hardware based or PC application based endpoints whether it crossed a boundary or not.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16119'
  tag rid: 'SV-17107r1_rule'
  tag stig_id: 'VVoIP 1020 (GENERAL)'
  tag gtitle: 'Deficient PPSM: Voice/Video/UC PPS Registration'
  tag fix_id: 'F-16225r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Disconnection of the system or service.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
