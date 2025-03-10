control 'SV-21737' do
  title 'All Customer Edge Routers (CE-R) implemented as the DISN access circuit termination point for the DISN NIPRNet IP Voice Services (IPVS) must be listed on the DoD Approved Products List (APL).'
  desc 'DISA has developed the DISN IPVS to support C2 Assured Service reliability and availability. As such, the worldwide availability and effectiveness of this service is dependent upon the components of the overall system that are located in each interconnected enclave. These components must be interoperable and support the needed quality of service. Therefore, if the VVoIP system in an enclave is to utilize the DISN IPVS to communicate with other enclaves across the NIPRNet, the system must be designed with equipment that has specific capabilities. Additionally, the implementation of VVoIP across the enclave boundary must not degrade the security or protection of the enclave. 

The CE-R provides the following functionality:
- Provides minimally four expedited forwarding queues (eight may be required in the future)
- Places traffic within expedited forwarding queues based on the DSCP markings carried by the traffic
- Routes AS-SIP-TLS packets and SRTP/SRTCP packets to the SBC function. (VVoIP firewall)
- Routes all other traffic to the data firewall
- Provides all of the filtering and security required by the Network Infrastructure STIGs

Use of the DISN IPVS network requires the following equipment to assure interoperability across the DISN service:
- At least one CE-R on which the DISN access circuits terminates
- At least one Local Session Controller (LSC), Enterprise Session Controllers (ESC), or Multi-Function Soft Switch (MFSS) within the enclave for session management
- A Session Border Controller (SBC) or data firewall having specific functionality as defined in the UCR will separate the CE-R from the LSC, ESC, and/or MFSS equipment.

NOTE: Proper DSCP marking of VVoIP packets is required to provide appropriate QoS for C2 priority calls in support of Assured Service.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

For VVoIP systems subscribed to the DISN NIPRNet IPVS network, ensure the boundary design includes one or more DoD APL listed CE-R(s) terminating the DISN access circuits. The CE-R must be robust/reliable and provide QOS features and capabilities as required by the UCR for the specific type of site. 

NOTE: If the DISN access circuits are dual homed, dual CE-Rs should be implemented unless a single CE-R can provide uninterrupted (5 9s) connectivity to the DISN.
NOTE: In the future this requirement may be applicable (with some modification) to the DISN SIPRNet IPVS (VoSIP) network when the PMO adopts the DISN NIPRNet IPVS architecture. 
NOTE: The CE-R must allow traditional SIP and SRTP traffic, and traffic encrypted and encapsulated on port 443 from Cloud Service Providers.

Determine, through interview and/or physical inspection, the specific make, model, and OS version of the CER. Access the DoD APL websites at listed below:
https://www.disa.mil/network-services/ucco
https://aplits.disa.mil/apl/
https://www.disa.mil/Network-Services/UCCO/APL-Removal-List

Verify all installed CE-Rs and software load (OS) versions are listed.

If all installed CE-Rs and software load (OS) versions are not listed, this is a finding.'
  desc 'fix', 'For VVoIP systems subscribed to the DISN NIPRNet IPVS network, ensure the boundary design includes one or more DoD APL listed CE-R(s) terminating the DISN access circuits. The CE-R must be robust/reliable and provide QOS features and capabilities as required by the UCR for the specific type of site. 
NOTE: If the DISN access circuits are dual homed, dual CERs should be implemented unless a single CER can provide uninterrupted (5 9s) connectivity to the DISN.
NOTE: In the future this requirement may be applicable (with some modification) to the DISN SIPRNet IPVS (VoSIP) network when the PMO adopts the DISN NIPRNet IPVS architecture. 
NOTE: The CE-R must allow traditional SIP and SRTP traffic, and traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23869r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19596'
  tag rid: 'SV-21737r2_rule'
  tag stig_id: 'VVoIP 6115'
  tag gtitle: 'VVoIP 6115'
  tag fix_id: 'F-20294r2_fix'
  tag 'documentable'
end
