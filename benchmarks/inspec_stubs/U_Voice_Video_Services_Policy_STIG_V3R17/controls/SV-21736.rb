control 'SV-21736' do
  title 'The VVoIP system within the enclave is not subscribed to or integrated with the worldwide DISN IPVS network operating on the appropriately classified DISN IP WAN service'
  desc 'DISN IP based C2 Assured Service is about providing a highly available and reliable communications voice, video, and data service on a world wide scale that supports the command and control (C2) of military forces by all levels of command, from the lower echelons up to the president. While this is relatively easy for data transmission, this is not an easy task for voice and video communications, particularly when the state of the art for VoIP communications today has developed along different paths followed by each vendor. As such, VoIP communications has not been interoperable between different vendor’s systems or between these systems and the various VoIP services that are available today. The task is made more difficult by the fact that the transport medium, that is IP networks, are generally not designed to transport time sensitive communications. Information contained in packets is transported in a manner that ensures the information will get to its destination reliably, although not in a specific amount of time. This is not acceptable for packetized voice and video since lost or delayed packets affects intelligibility of the communications. An additional aspect of assured service voice communications is that of call or message priority. Some calls, that are high priority C2 calls, must be completed at the expense of lower priority or routine calls. DISA has worked to overcome these issues by working with the many vendors that provide telecommunications equipment to the DoD to develop a highly available, reliable, and interoperable IP based assured service voice and video communications network to meet the needs of its C2 customers. Additional DoD policy dictates that DISN services be used as the first choice for DoD components to fulfill their long haul communications needs. For dialup voice, video, and data services the Defense Switched Network (DSN) has fulfilled this role for sensitive but unclassified communications. Similarly the Defense RED Switched Network (DRSN) has fulfilled this role for multi-level classified voice communications. 

As DoD migrates to an all IP based DISN, the IP based voice services with the addition of video will fulfill this role into the future. A single vendor, classified, secret level, IP voice communications system has been implemented on SIPRNet which is currently called VoSIP. VoSIP stands for Voice over Secret (or secure) IP. This service and the supporting network are expected to provide assured service in the future. 

For the purpose of this document, assured voice/video communications services (classified or unclassified) on the DISN is designated as DISN IP Voice Services (IPVS). 

As such, if the VVoIP system within the enclave connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications between enclaves to any level of C2 user (Special C2, C2, C2(R)), the system must be integrated with (or subscribed to) the worldwide DISN IPVS network operating on the appropriately classified DISN IP WAN service.

NOTE: an exception might be given for private VVoIP communications systems implemented amongst a small community of interest to fulfill a validated mission requirement.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the VVoIP system within the enclave connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications between enclaves to any level of C2 user (Special C2, C2, C2(R)), ensure the system is integrated with (subscribed to) the worldwide DISN IPVS network operating on the appropriately classified DISN IP WAN service (i.e., DISN NIPRNet IP Voice Services (IPVS) or DISN SIPRNet IP Voice Services (IPVS) otherwise known as VoSIP).
NOTE: an exception is given for an enclave that is part of an Intranet if the intranet as a whole is subscribed to the appropriate DISN IPVS.
NOTE: An exception is given for private VVoIP communications systems implemented amongst a small community of interest to fulfill a validated mission requirement. In this case, the system is essentially an intercom even though it might span enclave boundaries and the DISN.

Determine if the system is used to provide assured service communications between enclaves to any level of C2 user (Special C2, C2, C2(R)).
 
This is a finding in the event the VVoIP system within the enclave is connected to the DISN WAN for VVoIP transport but is not subscribes to or integrated with the DISN IPVS implemented on NIPRNet or SIPRNet. 

This is not a finding in the event the VVoIP system within the enclave is integrated with a service level Intranet or if it is implemented as a private communications system (e.g., intercom) implemented amongst a small community of interest to fulfill a validated mission requirement.'
  desc 'fix', 'In the event the VVoIP system within the enclave connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications between enclaves to any level of C2 user (Special C2, C2, C2(R)), ensure the system is integrated with (subscribed to) the worldwide DISN IPVS network operating on the appropriately classified DISN IP WAN service (i.e., DISN NIPRNet IP Voice Services (IPVS) or DISN SIPRNet IP Voice Services (IPVS) otherwise known as VoSIP).'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19595'
  tag rid: 'SV-21736r1_rule'
  tag stig_id: 'VVoIP 6105 (DISN-IPVS)'
  tag gtitle: 'Deficient DISN IPVS integration for C2 support'
  tag fix_id: 'F-20293r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'The inability to make precedence or priority calls across the DISN in support of C2 assured service communications.'
  tag responsibility: 'Information Assurance Officer'
end
