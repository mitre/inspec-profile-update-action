control 'SV-21735' do
  title 'The VVoIP system connection to the DISN WAN, its components, and/or changes to them are not included in the site’s enclave / LAN baseline documentation and C&A documentation.'
  desc 'Documentation of the enclave / LAN configuration must include all VVoIP systems. If the current configuration cannot be determined then it is difficult to apply security policies effectively. Security is particularly important for VoIP technologies attached to the enclave network because these systems increase the potential for eavesdropping and other unauthorized access to network resources. Accurate network documentation is critical to maintaining the network and understanding its security posture, threats, and vulnerabilities. Baseline and C&A documentation is the vehicle by which the DAA receives security related information on the network for which he/she is personally responsible and accepts the security risk of operating the system. Additionally, When subscribing to DISN NIPRNet IP Voice Services (IPVS) or DISN SIPRNet IP Voice Services (IPVS) otherwise known as VoSIP, Or if the system connects to the DISN WAN for VVoIP transport between enclaves (such as in an Intranet), the enclave(s) must update their LAN / Enclave C&A and CAP documentation. The site must then seek an updated ATO/ATC or if necessary an IATO/IATC for the enclave’s connection to the DISN for VVoIP from the appropriate DISN CAP office (UCAO or CCAO). Without connection approval the site will not be included in the DISN Voice Services dial plan.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement: 

In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves, ensure the VVoIP system’s WAN connection and boundary as well as its components including as their upgrades and changes are included in the site’s enclave / LAN C&A documentation (i.e., the DIACAP Implementation Plan (DIP), System Identification Profile (SIP), Scorecard, etc.). 

> Review the baseline documentation and/or C&A documentation to verify that the VVoIP WAN boundary and/or modifications are included. Verify there is a procedure for approving changes to configuration.'
  desc 'fix', 'In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves, ensure the VVoIP system’s WAN connection and boundary as well as its components including as their upgrades and changes are included in the site’s enclave / LAN C&A documentation (i.e., the DIACAP Implementation Plan (DIP), System Identification Profile (SIP), Scorecard, etc). 

Add the VVoIP WAN boundary and/or its modifications to the site’s enclave / LAN baseline and C&A documentation Obtain DAA approval for the updated documentation. Submit to the SRR team lead for validation and finding closure.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23866r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19594'
  tag rid: 'SV-21735r1_rule'
  tag stig_id: 'VVoIP 6100 (DISN-IPVS)'
  tag gtitle: 'Deficient C&A: VVoIP DISN Bndry in LAN C&A doc’n'
  tag fix_id: 'F-20292r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'The inability to effectively maintain the network or voice service and apply security policy and vulnerability mitigations. The inability for the DAA to understand the voice system’s and/or network’s security posture, threats, and vulnerabilities. The inability for the DAA to approve or accept the security risk of operating the system'
  tag responsibility: 'Information Assurance Officer'
end
