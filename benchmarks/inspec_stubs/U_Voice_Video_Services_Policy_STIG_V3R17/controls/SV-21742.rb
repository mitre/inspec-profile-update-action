control 'SV-21742' do
  title 'The enclave is NOT dual homed to two geographically diverse DISN SDNs and DISN WAN Service (NIPRNet or SIPRNet) Aggregation Routers (AR) or DISN Provider Edge (PE) routers.'
  desc 'Redundancy and dual homing is used within the DISN core to provide for continuity of operations (COOP) in the event a piece of equipment, circuit path, or even an entire service delivery node is lost. DoD policy also requires DoD enclaves that support C2 users for data services to be dual homed to the DISN core SDNs. This means that there will be two physically separate access circuits from the enclave to two geographically diverse DISN SDNs. Once the access circuits arrive at the SDNs, the circuits need to be connected to two geographically diverse DISN WAN Service (NIPRNet or SIPRNet) Aggregation Routers (AR) or DISN Provider Edge (PE) routers. Depending upon the size of the SDN, one or both of the access circuits must be extended to another SDN containing the AR or PE. AR’s are also dual homed to geographically diverse DISN PE routers. A single circuit provides far less redundancy and reliability than dual circuits This redundancy is required to increase the availability of the access to the DISN core so that there is more chance that assured service can be achieved. This need extends to assured service C2 VVoIP communications and is why we check it here.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure the enclave is dual homed to two geographically diverse DISN SDNs and DISN WAN Service (NIPRNet or SIPRNet)  Aggregation Routers (AR) or DISN Provider Edge (PE) routers.

NOTE: This means there are two DISN (or commercial) access circuits (many circuits will have a commercial component, typically the “last mile”) from the site/enclave to the DISN SDNs.

NOTE: This assumes the site/enclave is NOT collocated with a DISN SDN such that a direct Ethernet or optical connection can be made. 

NOTE: If a site is located at a DISN SDN and is able to directly connect to the SDN using Ethernet or optical connections, the site may be able to rely on the dual homing of the SDN into the core. However, the site must still be homed to two geographically diverse ARs. This is dependant upon the size or type of the SDN. A large site directly connected to a smaller SDN will implement an access circuit to a geographically diverse SDN (i.e., another SDN in another location remote from the local SDN. This should not be one of the SDNs that to which the local SDN is homed. 

Determine if the site supports any level of C2 user. Determine how many access circuits are implemented and to what SDN they are homed. Additionally, determine the ARs or PEs to which the enclave is homed.

This is a finding in the event the site is a C2 site and the DISN access circuits between the enclave’s WAN boundary and the DISN is not redundant and diverse as described in the requirement and notes. 

This is not a finding in the event the site does not support any level of C2 user.'
  desc 'fix', 'In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure the enclave is dual homed to two geographically diverse DISN SDNs and DISN WAN Service (NIPRNet or SIPRNet)  routers.

NOTE: This means there are two DISN (or commercial) access circuits (many circuits will have a commercial component, typically the “last mile”) from the site/enclave to the DISN SDNs.

NOTE: This assumes the site/enclave is NOT collocated with a DISN SDN such that a direct Ethernet or optical connection can be made.. 

NOTE: If a site is located at a DISN SDN and is able to directly connect to the SDN using Ethernet or optical connections, the site may be able to rely on the dual homing of the SDN into the core. However, the site must still be homed to two geographically diverse ARs. This is dependant upon the size or type of the SDN. A large site directly connected to a smaller SDN will implement an access circuit to a geographically diverse SDN (i.e., another SDN in another location remote from the local SDN. This should not be one of the SDNs that to which the local SDN is homed.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19601'
  tag rid: 'SV-21742r1_rule'
  tag stig_id: 'VVoIP 6135 (DISN-IPVS)'
  tag gtitle: 'Deficient imp’n: C2 enclave; Dual Homed Circuits'
  tag fix_id: 'F-20300r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Reduced availability and the inability to complete a C2 call'
  tag responsibility: 'Information Assurance Officer'
end
