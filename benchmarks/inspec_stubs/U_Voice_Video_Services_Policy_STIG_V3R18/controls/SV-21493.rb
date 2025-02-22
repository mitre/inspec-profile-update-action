control 'SV-21493' do
  title 'The site’s V-VoIP system is NOT capable of maintaining call/session establishment capability such that it can minimally make local internal and local commercial network calls in the event the LSC or MFSS becomes unavailable to receive and act on EI signaling requests.'
  desc 'Voice phone services are critical to the effective operation of a business, an office, or in support or control of a DoD mission. We rely on these services being available when they are needed. Additionally, it is critical that phone service is available in the event of an emergency situation such as a security breach or life safety event. The capability or ability to place calls to emergency services must be maintained. While the DoD voice and data networks are designed to be extremely reliable, such that continuity of operations (COOP) is supported, there is the potential that a site’s EIs will loose the availability to communicate or signal with the LSC or MFSS. Reality is that if signaling messages cannot reach a LSC or MFSS, calls cannot be established. This is an issue even though the LSC and MFSS are specified to provide 5 9s availability; there are many other factors that affect the availability of these central devices. Natural disasters or physical damage to the network connections and/or pathways are just some. The following are considerations for meeting this requirement: 
• Large sites and Intranets: 
•• Redundancy of platforms – Two or more LSC controllers clustered o  Geographic diversity in locating the multiple LSCs within the site or Intranet 
• Small Sites (not dual homed): 
•• A single local subtended LSC may use a LSC to which it is subtended as the backup LSC for call control in the event the local LSC goes down. The best method for meeting this requirement on a large site is to implement redundancy for the LSC and the LSC portion of a MFSS. These redundant devices would then be located in redundant and geographically diverse facilities and connected to different parts of the LAN or CAN. This would mean that two core locations would be established within the site/enclave. LSCs and the LSC portion of a MFSS may be implemented on redundant platforms to meet the 5 9s availability requirements. Potentially these internally redundant devices might be able to be decomposed and located in the redundant facilities. Additional protections are needed for the communications between these decomposed elements. Additionally, each portion of the decomposed elements would need to be able to function on its own. In the event a site/enclave supports multiple tenants and one or more of these tenants have their own LSC, the main site could establish a COOP relationship with the tenant LSC and vise versa. An alternate method might be to establish a COOP relationship to a LSC or MFSS in another site or enclave. The issue with this arrangement is that the interconnection between sites is vulnerable and should be redundant with potentially COOP relationships with multiple LSCs at multiple sites. The best method for an Intranet served by a central LSC or MFSS is to place redundant LSCs in redundant and geographically diverse facilities which are then connected to different parts of the Intranet. Sites served by these LSCs should be dual homed using redundant circuits via geographically diverse paths.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

Ensure all sites possessing a LSC or MFSS are capable of maintaining call/session establishment capability such that it can minimally make local internal and local commercial network calls in the event the LSC or MFSS becomes unavailable to receive and act on EI signaling requests. 

Determine if the LSC or LSC portion of the MFSS has a backup call/session establishment capability such that it can minimally make local internal and local commercial network calls

This is a finding in the event the primary LSC or LSC portion of the MFSS has no COOP relationship with another LSC in a redundant and geographically diverse facility.

NOTE: The minimum capability for placement of precedence calls (line-side or to the DISN) is dependant upon the C2 requirements of the site in question and should be determined in conjunction with the local command authority. To satisfy this requirement, however, the minimum requirement is the maintenance of ROUTINE call placement capabilities.'
  desc 'fix', 'Establish COOP capabilities for the primary LSC or LSC portion of the MFSS using redundant LSCs or COOP arrangements with other LSCs in redundant and geographically diverse facilities.

NOTE: The minimum capability for placement of precedence calls (line-side or to the DISN)is dependant upon the C2 requirements of the site in question and should be determined in conjunction with the local command authority. To satisfy this requirement, however, the minimum requirement is the maintenance of ROUTINE call placement capabilities.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23706r1_chk'
  tag severity: 'low'
  tag gid: 'V-19442'
  tag rid: 'SV-21493r1_rule'
  tag stig_id: 'VVoIP 1210 (GENERAL)'
  tag gtitle: 'Deficient COOP: LSC / MFSS - Backup LSC'
  tag fix_id: 'F-20186r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'The inability to use the V-VoIP system to communicate'
  tag responsibility: 'Information Assurance Officer'
end
