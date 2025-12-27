control 'SV-21741' do
  title 'The DISN Core access circuit is NOT properly sized to accommodate the calculated Assured Service Admission Control (ASAC) budgets for AS voice and video calls/sessions OR the required budgets have not been calculated.'
  desc 'The DISN NIPRNet IPVS PMO has developed a method to provide Assured Service voice and video communications over the bandwidth constrained portion of the DISN. This method includes or supports providing precedence and priority capabilities for C2 users similar to the MLPP service provided by the traditional TDM based DSN. The enclave’s internal LAN is required to be designed to be non-blocking. That is it must provide ample bandwidth for all the traffic that it is expected to carry. This is controllable by DoD. On the other hand, the DISN Core is designed to have ample bandwidth and expandability to support what ever traffic the DoD enclaves throw at it. As such it is considered to be bandwidth rich. Due to issues surrounding the ability for an attached enclave to determine the bandwidth availability or congestion conditions within the core in real time, an assumption has to be made that the DISN Core is also non-blocking. The DISN Core bandwidth is also controllable by DoD. The portion of the overall DISN network that is bandwidth constrained is the TDM or optical OCx access circuits between the local enclave and the DISN Core. This is the portion of the network where we have the least control over bandwidth availability, primarily due to the cost of these circuits. The cost factor is an issue since many DISN access circuits must rely on commercial carriers for some portion of the overall circuit. This is typically the portion that delivers the DISN service to the B/C/P/S. Access circuit issues are less of an issue if the B/C/P/S also provides a home for one of the DISN Core SDNs. This is because a direct connection can be made between the CER and the SDN, however, the circuit capacity may still be an issue if the SDN is a small one that does not have an AR or PE. Due to the nature of digital transmission over these bandwidth constrained circuits, the quality and availability of the communications is degraded as these circuits become congested. “Data” packets can wait until processed without negatively affecting the delivery of a message. This is not the case for VVoIP due to its time sensitive nature (it is a real time service). If VVoIP packets have to wait for transmission, the quality of the call suffers. In IA terms, this relates to the availability of the service and quality communications. To overcome the bandwidth constraints inherent in WAN access circuits, an engineered bandwidth budget must be developed for each service (voice, video, and data) using the circuit. Voice and video budgets are developed in terms of call or session counts. For example, the UCR defines a voice call as follows: “One voice session budget unit shall be equivalent to 110 kilobits per second (kbps) of access circuit bandwidth independent of the EI codec used. This includes ITUT Recommendation G.711 encoding rate plus Internet Protocol Version 6 (IPv6) packet overhead plus ASLAN Ethernet overhead. IPv6 overhead, not IPv4 overhead, is used to determine bandwidth equivalents here.” 

NOTE: This budget is unidirectional and must be doubled for bi-directional communications sessions. 

NOTE: The VoIP budget covers the following types of services: Voice VoIP, FoIP, MoIP, or SCIP over IP calls The UCR also defines a video call as follows: “Since the bandwidth of a video session can vary [depending upon video resolution (ed)], video sessions will be budgeted in terms of video session units (VSUs). One VSU equals 500 kbps and bandwidth for video sessions will be allocated in multiples of VSUs. For example, the bandwidth allocated to video sessions may be 500 kbps, 1000 kbps, and 2500 kbps. Thus, a video session that requires 2500 kbps will be allocated five VSUs.” 

NOTE: This discussion, as it relates to video, is in regard to video sessions controlled by the LSC using AS-SIP for the signaling protocol. H.323 signaled video and/or VTC sessions must be considered separately and potentially have their own budget for access circuit bandwidth. 

NOTE: This budget (which also includes the audio component) is unidirectional and must be doubled for bi-directional communications sessions. When developing the bandwidth budgets, the engineer must determine how many simultaneous voice and video calls/sessions are to be supported by the access circuit based upon the unit per call defined in the UCR. The bandwidth budget to be reserved for voice is then calculated along with a budget for video. Next the engineer must determine what percentage of the overall access circuit bandwidth these reserved budgets should consume. The access circuit is then sized (ordered) to accommodate the needs. It is not recommended that IP voice and video capabilities be added to an existing circuit since this would mean the call/session counts would have to be restricted or the data budget would have to be squeezed. 

NOTE: Data traffic is permitted to surge into the voice and video budgets if the bandwidth is available; however the voice and video budgets are reserved and will be reclaimed if needed. Voice and video is not permitted to surge into the data budget since ASAC needs a fixed call count to be effective. 

NOTE: Instructions for determining voice call budgets for a DISN WAN access circuit can be found in the UCR section 5.3.3.11 Provisioning'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure Session Admission Control (SAC) for the DISN Core access circuit(s) is supported by engineered bandwidth budgets for VoIP and Video calls/sessions in support of Assured Service.
NOTE: SAC in support of Assured Service is also referred to as Assured Service Admission Control (ASAC)
NOTE: The VoIP budget covers the following types of services: Voice VoIP, FoIP, MoIP, or SCIP over IP calls
NOTE: Per call/session units are defined in the UCR and are unidirectional. They must be doubled to support bi-directional communications between users which is the typical phone call. 

This is a finding in the event there is no evidence that the required budgets have been calculated and/or the access circuit has not been sized accordingly.'
  desc 'fix', 'In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure Session Admission Control (SAC) for the DISN Core access circuit(s) is supported by engineered bandwidth budgets for VoIP and Video calls/sessions in support of Assured Service.
NOTE: SAC in support of Assured Service is also referred to as Assured Service Admission Control (ASAC)
NOTE: The VoIP budget covers the following types of services:
Voice VoIP, FoIP, MoIP, or SCIP over IP calls
NOTE: Per call/session units are defined in the UCR and are unidirectional. They must be doubled to support bi-directional communications between users which is the typical phone call. 
NOTE: Instructions for determining voice call budgets for a DISN WAN access circuit can be found in the UCR section 5.3.3.11 Provisioning'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19600'
  tag rid: 'SV-21741r1_rule'
  tag stig_id: 'VVoIP 6155 (DISN-IPVS)'
  tag gtitle: 'Deficient Design: Access Circuit Call Budgets'
  tag fix_id: 'F-20299r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Reduced service availability and the inability to place a priority call'
  tag responsibility: 'Information Assurance Officer'
end
