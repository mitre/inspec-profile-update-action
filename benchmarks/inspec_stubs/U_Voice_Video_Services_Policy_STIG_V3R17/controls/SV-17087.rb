control 'SV-17087' do
  title 'The architecture and/or configuration of a permanent, semi-permanent, or fixed (not highly mobile) tactical LAN supporting IP based voice, video, unified, and/or collaboration communications is not adequate to protect the VVoIP services and infrastructure.'
  desc 'The primary reason for the implementation of the LAN architecture and security measures defined in this and other STIGs is to improve the survivability (availability) of the VVoIP communications service in whatever environment it is deployed. These measures are designed to protect the VVoIP service and infrastructure to the greatest extent possible in the event there is a compromise of an OS or application on a workstation or server attached to the data side of the LAN. If this occurs, the compromised platform could be used by an adversary to compromise the VVoIP communications or its supporting infrastructure. Such compromise can happen rather easily, particularly when a server is a web or application server or a workstation is used for web surfing or email. A secondary reason for the implementation of the LAN architecture and security measures defined is to help protect the confidentiality and integrity of the supported VVoIP communications. Based on these two reasons, the defined VVoIP architecture serves to segregate and hide the VVoIP communications and infrastructure (to the greatest extent possible on a converged LAN) from the data workstation users and associated platforms. While VVoIP systems deployed on a strategic B/C/P/S provide a combination of general business or administrative communications along with C2 communications, tactical deployments primarily support C2 communications. There is nowhere other than a tactical deployment that the availability, confidentiality, and integrity of a VVoIP communications service is as critical. Therefore the network supporting a tactical VVoIP communications system must follow the same guidelines as a network supporting a strategic VVoIP system or application. 

NOTE: Initial deployments may include as little as a half dozen workstations or as many as fifty. Once the initial deployment is in place, the network may grow and become relatively permanent as would be the case for a rear command or logistics center. 
NOTE: A shipboard LAN is minimally considered as a fixed tactical LAN but can also be considered as a Strategic LAN. This is because the installation is permanent within the confines of the mobile floating base. In other words, the base (AKA ship) moves without disrupting the LAN.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure permanent, semi-permanent, or fixed (not highly mobile) tactical networks supporting IP based voice, video, unified, and/or collaboration communications are configured per the requirements for a strategic LAN supporting voice/video/UC services.

Determine if the tactical LAN is supporting a fixed or generally non-moving base making it a fixed tactical LAN. If the fixed tactical network supports IP based voice, video, UC, and/or collaboration communications, determine if it is configured per the requirements for a strategic LAN. Inspect network diagrams and interview the IAO to determine compliance. 

This is a finding in the event the deployed tactical network is relatively permanent compared to a small highly mobile unit and the LAN is not configured as a strategic LAN for the support of supports IP based voice, video, UC, and/or collaboration communications as defined in this and other STIGs.

NOTE: The factors determining whether a deployed tactical VVoIP system is subject to this requirement are varied. In general all VVoIP systems should be configured the same and such that the service and supporting infrastructure is protected. It is recognized that a small system operated out of a transit case in a tent, conex box, or a truck is highly mobile as opposed to a fixed installation in a building. While initially such a system can support a few users and remain highly mobile, as the number of users increases, the deployment becomes semi-permanent, or fixed (not highly mobile). Initial deployments may include as little as a half dozen workstations or as many as fifty. Once the initial deployment is in place, the network may grow and become relatively permanent as would be the case for a rear command or logistics center. Small deployable packages that are designed to be initially deployed with a small footprint supporting or using PC soft-phones, which are then to be the basis of a larger network, must be configured, or be configurable, to support the separate VoIP and data zones as well as hardware based instruments and admission control for C2 communications as the deployed network and supported systems grow. The network will also include soft-phone protection zones as required in a strategic network if soft-phones are permitted to be used beyond the initial deployment. 
NOTE: A shipboard LAN is minimally considered as a fixed tactical LAN but can also be considered as a Strategic LAN. This is because the installation is permanent within the confines of the mobile floating base.'
  desc 'fix', 'Ensure permanent, semi-permanent, or fixed (not highly mobile) tactical networks supporting IP based voice, video, unified, and/or collaboration communications are configured per the requirements for a strategic LAN.

Configure the fixed tactical LAN in accordance with the requirements for a strategic LAN that supports IP based voice, video, UC, and/or collaboration communications.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17143r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16099'
  tag rid: 'SV-17087r1_rule'
  tag stig_id: 'VVoIP 1925 (GENERAL)'
  tag gtitle: 'Deficient Network Architecture: Fixed Tactical'
  tag fix_id: 'F-16204r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This finding can be reduced to a CAT III in the event VVoIP 1930 is not a finding. VVoIP 1930 requires a benefit vs. risk analysis be performed and approval for reduced VVoIP IA configuration measures in highly mobile tactical LANs and systems supporting hardware or PC based voice, video, unified, and/or collaboration communications.'
  tag potential_impacts: 'Increased potential for the compromise of the VVoIP controllers, gateways, hardware based instruments, and other VVoIP infrastructure. Possible degradation of service on the hardware based phone system.
Reduced availability, confidentiality, and integrity of the VVoIP service.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
