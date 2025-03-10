control 'SV-21738' do
  title 'A Session Border Controller (SBC) implemented as the DISN boundary element  for the DISN NIPRNet IP Voice Services (IPVS) must be listed on the DoD Approved Products List (APL).'
  desc 'DISA has developed the DISN IPVS to support C2 Assured Service reliability and availability. As such, the worldwide availability and effectiveness of this service is dependent upon the components of the overall system that are located in each interconnected enclave. These components must be interoperable and support the needed quality of service. Therefore, if the VVoIP system in an enclave is to utilize the DISN IPVS to communicate with other enclaves across the NIPRNet, the system must be designed with equipment that has specific capabilities. Additionally, the implementation of VVoIP across the enclave boundary must not degrade the security or protection of the enclave. 

Use of the DISN IPVS network requires the following equipment to assure interoperability across the DISN service:
- At least one Customer Edge Router (CE-R) on which the DISN access circuits terminates
- At least one Local Session Controller (LSC), Enterprise Session Controllers (ESC), or Multi-Function Soft Switch (MFSS) within the enclave for session management
- An SBC or data firewall having specific functionality as defined in the UCR will separate the CE-R from the LSC, ESC, and/or MFSS equipment'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

For VVoIP systems subscribed to the DISN NIPRNet IPVS network, ensure a DoD APL listed Session Border Controller (SBC) is implemented at the enclave boundary between the CER and LSC/ESC/MFSS to maintain the required enclave boundary protection while permitting DISN IPVS traffic to pass.

NOTE: The SBC may be a dedicated device or may be part of the required data firewall. 
NOTE: In the future this requirement may be applicable (with some modification) to the DISN SIPRNet IPVS (VoSIP) network when the PMO adopts the DISN NIPRNet IPVS architecture. 
NOTE: The SBC may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.

Determine, through interview and/or physical inspection, the specific make, model, and OS version of the SBC. Access the DoD APL websites at listed below:
https://www.disa.mil/network-services/ucco
https://aplits.disa.mil/apl/
https://www.disa.mil/Network-Services/UCCO/APL-Removal-List

Verify all installed SBCs and software load (OS) versions are listed.

If all installed SBCs and software load (OS) versions are not listed, this is a finding.'
  desc 'fix', 'For VVoIP systems subscribed to the DISN NIPRNet IPVS network, ensure a DoD APL listed Session Border Controller (SBC) is implemented at the enclave boundary between the CER and LSC/ESC/MFSS to maintain the required enclave boundary protection while permitting DISN IPVS traffic to pass. 

NOTE: The SBC may be a dedicated device or may be part of the required data firewall. 
NOTE: In the future this requirement may be applicable (with some modification) to the DISN SIPRNet IPVS (VoSIP) network when the PMO adopts the DISN NIPRNet IPVS architecture. 
NOTE: The SBC may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23871r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19597'
  tag rid: 'SV-21738r2_rule'
  tag stig_id: 'VVoIP 6120'
  tag gtitle: 'VVoIP 6120'
  tag fix_id: 'F-20296r2_fix'
  tag 'documentable'
end
