control 'SV-17089' do
  title 'Deficient benefit vs. risk analysis and/or approval for reduced VVoIP IA configuration measures in highly mobile tactical LANs and systems supporting hardware or PC based voice, video, unified, and/or collaboration communications.'
  desc 'As discussed above, the network supporting a tactical VVoIP communications system must follow the same guidelines as a network supporting a strategic VVoIP system or application to help ensure the availability, confidentiality, and integrity of the communications service.

An argument could be made that a tactical LAN and attached workstations might be less prone to compromise than a strategic LAN and its attached workstations therefore we do not need all these security measures for VoIP. This argument might be supported by the smaller size of a tactical LAN, particularly an initially deployed system, mission duration, and the ability to limit its usage to tactical applications. Unfortunately if the tactical LAN is connected to NIPRNet or the strategic LAN at the home base, it can still be compromised particularly if general web browsing is permitted and performed and email is used. Additionally, there is nowhere that C2 communications is more important than in the tactical LAN. Any decision to eliminate any of the protective measures for the C2 voice service that could negatively impact its reliability must be based in a risk assessment that weighs the benefits against the risks. Deployable packages that are designed to be initially deployed with a small footprint supporting or using PC soft-phones, which are then to be the basis of a larger network, must be configured, or be configurable, to support the separate VoIP and data zones as well as hardware based instruments and admission control for C2 communications as the deployed network and supported systems grow. The network will also include soft-phone protection zones as required in a strategic network if soft-phones are permitted to be used beyond the initial deployment. In general, larger relatively permanent tactical networks should be configured the same as a strategic network since similar vulnerabilities exist. 

As a result, if IA measures are to be relaxed for a highly mobile tactical network or deployable package, the reduction must be supported by an approved benefit vs. risk analysis. Approval must be given by the person or entity responsible for accepting the risk of operating the VVoIP system in a vulnerable manner.

NOTE: This requirement does not apply to shipboard LANs since they are permanently installed.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

In the event voice/video/UC IA configuration measures are reduced for highly mobile tactical networks (e.g., initial deployment packages) supporting hardware or PC based voice, video, unified, and/or collaboration communications, the IAO will ensure a benefit vs. risk analysis is performed, documented, and approved in the certification and accreditation of the system.

NOTE: It is recognized that deployable packages for highly mobile tactical networks may only support PC based voice, video, UC, and/or collaboration communications applications. Such a network may not require separate zones for voice and data since all traffic will be in the data zone.

Determine if IA configuration measures are reduced for highly mobile tactical networks (e.g., initial deployment packages) supporting hardware or PC based voice, video, UC, and/or collaboration communications. If so, inspect network diagrams and device configurations to determine the IA measures implemented. If the implemented IA measures are reduced from those required in a strategic or fixed tactical LAN, inspect the documented benefit vs. risk analysis used in the C&A process for the system.

This is a finding if there is no benefit vs. risk analysis, or it is found to be deficient in some manner, such that the appropriate risk level was not used in the C&A of the system.'
  desc 'fix', 'In the event voice/video/UC IA configuration measures are reduced for highly mobile tactical networks (e.g., initial deployment packages) supporting hardware or PC based voice, video, unified, and/or collaboration communications, perform and document a benefit vs. risk analysis for the reduced IA measures and update the C&A for the system.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17144r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16101'
  tag rid: 'SV-17089r1_rule'
  tag stig_id: 'VVoIP 1930 (GENERAL)'
  tag gtitle: 'Deficient Risk Analysis: Mobile Tactical Arch.'
  tag fix_id: 'F-16205r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Increased potential for the compromise of the VVoIP controllers, gateways, hardware based instruments, and other VVoIP infrastructure. Possible degradation of service on the hardware based phone system.
Reduced availability, confidentiality, and integrity of the VVoIP service.'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
end
