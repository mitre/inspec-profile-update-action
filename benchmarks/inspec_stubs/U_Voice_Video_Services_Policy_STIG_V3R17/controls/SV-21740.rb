control 'SV-21740' do
  title 'All Local Session Controllers (LSC), Enterprise Session Controllers (ESC), and Multi-Function Soft Switches (MFSS) implemented within the enclave to provide session management for the DISN NIPRNet IP Voice Services (IPVS) must be listed on the DoD Approved Products List (APL).'
  desc 'DISA has developed the DISN IPVS to support C2 Assured Service reliability and availability. As such, the worldwide availability and effectiveness of this service is dependent upon the components of the overall system that are located in each interconnected enclave. These components must be interoperable and support the needed quality of service. Therefore, if the VVoIP system in an enclave is to utilize the DISN IPVS to communicate with other enclaves across the NIPRNet, the system must be designed with equipment that has specific capabilities. Additionally, the implementation of VVoIP across the enclave boundary must not degrade the security or protection of the enclave. 


Use of the DISN IPVS network requires the following equipment to assure interoperability across the DISN service:
- At least one Customer Edge Router (CE-R) on which the DISN access circuits terminates
- At least one LSC, ESC, or MFSS within the enclave for session management
- A Session Border Controller (SBC) or data firewall having specific functionality as defined in the UCR will separate the CE-R from the LSC, ESC, and/or MFSS equipment

NOTE: For a large facility (site) the primary session controller should have a backup session controller geographically separate from it. This is also applicable to a facility/site using a MFSS. While the MFSS work in pairs in the backbone and are therefore redundant with regard to backbone services, their session controller functionality should also be redundant.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

For VVoIP systems within the enclave integrated with the unclassified or classified DISN IPVS network, ensure the system is designed to include at least one LSC, ESC, or MFSS for session control within the enclave. 

NOTE: The LSC/ESC (one or more per site) manages local endpoint registration and calls established to/from local endpoints and facilities. Also manages calls into and out of the enclave. The MFSS (one per site and potentially a backup LSC/ESC) performs session control functions for its site and provides signaling management for a regional set of session controllers. An MFSS is a backbone device and is only required at DISN IPVS PMO designated locations.
NOTE: The LSC and MFSS are robust/reliable and provide admission control, and QoS features / capabilities as required by the UCR.
NOTE: The session controllers may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.

Determine, through interview and/or physical inspection, the specific make, model, and OS version of all LSCs, ESCs, and MFSS. Access the DoD APL websites at listed below:
https://www.disa.mil/network-services/ucco
https://aplits.disa.mil/apl/
https://www.disa.mil/Network-Services/UCCO/APL-Removal-List

Verify all installed LSCs, ESCs, and MFSS and software load (OS) versions are listed.

If all installed LSCs, ESCs, and MFSS and software load (OS) versions are not listed, this is a finding.'
  desc 'fix', 'For VVoIP systems within the enclave integrated with the unclassified or classified DISN IPVS network, ensure the system is designed to include at least one LSC, ESC, or MFSS for session control within the enclave.

NOTE: The LSC/ESC (one or more per site) manages local endpoint registration and calls established to/from local endpoints and facilities. Also manages calls into and out of the enclave. The MFSS (one per site and potentially a backup LSC/ESC) performs session control functions for its site and provides signaling management for a regional set of session controllers. An MFSS is a backbone device and is only required at DISN IPVS PMO designated locations.
NOTE: The LSC and MFSS are robust/reliable and provide admission control, and QoS features / capabilities as required by the UCR.
NOTE: The session controllers may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23876r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19599'
  tag rid: 'SV-21740r2_rule'
  tag stig_id: 'VVoIP 6130'
  tag gtitle: 'VVoIP 6130'
  tag fix_id: 'F-20298r2_fix'
  tag 'documentable'
end
