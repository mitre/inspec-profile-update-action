control 'SV-8785' do
  title 'An inventory of authorized instruments is NOT documented or maintained in support of the detection of unauthorized instruments connected to the VoIP system.'
  desc 'Traditional telephone systems require physical wiring and/or switch configuration changes to add an instrument to the system. This makes it difficult for someone to add unauthorized digital instruments to the system. This, however, could be done easier with older analog systems by tapping an existing analog line. With VoIP, this is no longer the case. Most IPT/VoIP systems employ an automatic means of detecting and registering a new instrument on the network with the call management server and then downloading its configuration to the instrument. This presents a vulnerability whereby unauthorized instruments could be added to the system or instruments could be moved without authorization. Such activity can happen anywhere there is an active network port or outlet. This is not only a configuration management problem, but it could also allow theft of services or some other malicious attack. It is recognized however, that auto-registration is necessary during large deployments of VoIP terminals, as well as a short time thereafter, to facilitate additions and troubleshooting. This applies to initial system setup and to any subsequent large redeployments or additions. Normal, day to day, “moves, adds, and changes” will require manual registration. Since, it may be possible for an unauthorized VoIP terminal to easily be added to the system during auto-registration, the registration logs must be compared to the authorized terminal inventory. Alternately the system could have a method of automatically registering only pre-authorized terminals. This feature would support VoIP terminals that are DAA approved for connection from multiple local or remote locations. It is critical to the security of the system that all IPT /VoIP end instruments be authorized to connect to and use the system. Only authorized instruments should be configured in the system controller and therefore allowed to operate. Unauthorized instruments could lead to system compromise or abuse. A manual inventory of authorized end instruments will aid in the detection of unauthorized instruments registered to the system particularly during the period when auto-detection/registration is permitted. This will also aid in C&A efforts.'
  desc 'check', 'Interview the IAO and review site documentation to confirm compliance with the following requirement: Ensure that an inventory of authorized instruments is documented and maintained.

Inspect the authorized instrument inventory.

NOTE: This inventory will be separate from the inventory created within the Local Session Controller (LSC) from the listing of registered instruments. Authorized instruments must be added to this inventory before configuration in the LSC and instrument registration. The inventory may be offline or online on a separate server or workstation from the LSC (for example, the LSC management workstation).

This is a finding if the inventory does not exist, does not appear to be up to date.

Ask how this inventory is generated and where it is stored. This is a finding in the event it is located on the LSC.'
  desc 'fix', 'Ensure that an inventory of authorized instruments is documented and maintained.
NOTE: This inventory will be separate from the inventory created within the Local Session Controller (LSC) from the listing of registered instruments. Authorized instruments must be added to this inventory before configuration in the LSC and instrument registration. The inventory may be offline or online on a separate server or workstation from the LSC (for example, the LSC management workstation).

Prepare and maintain an inventory / database of authorized VoIP instruments. Generate and store the inventory on a separate workstation or server from the LSC (for example, the LSC management workstation).

Recommendation: Create the inventory in a format that can easily be compared through automation to the report of registered instruments from the LSC (if available). This will facilitate regular review of the inventory to detect unauthorized instruments and will make the IA review easier.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-8290'
  tag rid: 'SV-8785r1_rule'
  tag stig_id: 'VVoIP 1505 (GENERAL)'
  tag gtitle: 'Deficient doc’n: Inventory of authorized endpoints'
  tag fix_id: 'F-20141r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Unauthorized use or abuse of the system'
  tag responsibility: 'Information Assurance Officer'
end
