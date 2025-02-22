control 'SV-8709' do
  title 'The VVoIP system, its components, and/or changes to them are not included in the site’s enclave / LAN baseline documentation and Configuration & Accreditation documentation'
  desc 'Documentation of the enclave / LAN configuration must include all VVoIP systems. If the current configuration cannot be determined then it is difficult to apply security policies effectively. Security is particularly important for VoIP technologies attached to the enclave network because these systems increase the potential for eavesdropping and other unauthorized access to network resources. Accurate network documentation is critical to maintaining the network and understanding its security posture, threats, and vulnerabilities. Baseline and C&A documentation is the vehicle by which the DAA receives security related information on the network for which he/she is personally responsible and accepts the security risk of operating the system.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement: Ensure the VVoIP and/or IP connected VTC system and its components as well as their upgrades and changes are included in the site’s enclave / LAN C&A documentation (e.g., the DIACAP Implementation Plan (DIP), System Identification Profile (SIP), Scorecard, etc.). 

NOTE: This requirement applies to or includes the existence or implementation of soft-phone applications or wireless VoIP (Wi-Fi or WiMAX) endpoints. 

> Review the baseline documentation and/or C&A documentation to verify that all VVoIP installations and/or modifications are included. Verify there is a procedure for approving changes to configuration.
> Determine if soft-phone applications or wireless VoIP (Wi-Fi or WiMAX) endpoints are used or implemented within the network. Look for the appearance of these in the required documentation noted above.'
  desc 'fix', 'Add all VoIP installations and/or modifications to the SSAA. Obtain DAA approval for the updated SSAA. Submit to the SRR team lead for validation and finding closure.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23599r1_chk'
  tag severity: 'low'
  tag gid: 'V-8223'
  tag rid: 'SV-8709r1_rule'
  tag stig_id: 'VVoIP 1100 (GENERAL)'
  tag gtitle: 'Deficient C&A: VVoIP System in LAN C&A doc’n'
  tag fix_id: 'F-7706r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'The inability to effectively maintain the network or voice service and apply security policy and vulnerability mitigations. The inability for the DAA to understand the voice system’s and/or network’s security posture, threats, and vulnerabilities. The inability for the DAA to approve or accept the security risk of operating the system'
  tag responsibility: 'Information Assurance Officer'
end
