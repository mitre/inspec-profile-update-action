control 'SV-17078' do
  title 'An acceptable use policy or user agreement must be enforced for Unified Capabilities (UC) soft client users.'
  desc "User agreements must be accompanied with a combination of user training and user guides reinforcing the organization's policies and prohibitions for UC soft clients (voice, video, and collaboration communications software clients). The user agreement is required in the DoD and must contain site policy and acceptable use of information system assets. Users must read and sign the user agreement before receiving government-furnished hardware or software. This extends to gaining access to additional information systems, adding on applications, or receiving additional privileges.

Policies must include acceptable use of the UC soft client application, UC soft client accessories, as well as web browsing, remote access, wireless use, and protection of controlled unclassified information (CUI). Minimally, the user agreement must be updated as privileges and additional applications are installed. User agreements must also be accompanied with user training and user guides that reinforce policies and provide additional relevant information."
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement:

Verify a user agreement is developed and enforced with users in accordance with DoD policies addressing the acceptable use of UC soft client applications and associated accessories minimally providing the following information:
- Users must not install any application or agent, to include UC soft clients, VTC software, or IM client that connects to or uses a public VoIP or IM service for non-official business.
- Users must not install any application or agent, to include UC soft clients, VTC software, or IM client that communicates peer-to-peer with other applications, agents, or personal phone gateways.
- Users must not use a USB or Ethernet subscriber line interface card (SLIC) associated with a commercial VoIP service (such as magicJack) or a personal VoIP system in the DoD unless the SLIC is sanctioned and provided by a DoD component or organization.
- Users must not use UC soft client accessories capable of bridging a DoD network or DoD application with another computer, phone network, or the PSTN.
- Users must not use DoD-provided UC soft client while working in their normal DoD workspace without permission of the ISSO. 
- Users must receive a caution notice discussing the non-assured nature of UC soft client applications for C2 user awareness that for assured service a UC soft client should not be the primary method of communications.
- Users must receive instruction for the proper and safe use of webcams or built-in cameras when used in a classified environment to prevent viewing classified work or classified material over non-secure networks.
- Users must receive instruction for the proper and safe use of speakerphones or built-in microphones when used in a classified environment to prevent hearing classified discussions over non-secure networks. 
- Users must receive instruction regarding the proper and safe use of presentation, document, and desktop sharing.

Sites may modify the above items in accordance with local site policy. However, each item must be addressed in the user agreement. A user agreement may be a standalone document or a larger document addressing remote access or workstation use that enforces the acceptable use of UC soft client applications and accessories. 

Discuss the existence and enforcement of the UC soft client acceptable use policy. Inspect signed user agreements for compliance. If no acceptable use policy or related user agreement exists, this is a finding. If the acceptable use policy or related user agreement is deficient in content, this is a finding.'
  desc 'fix', 'Develop and enforce a user agreement in accordance with DoD policies addressing the acceptable use of UC soft client applications and associated accessories minimally providing the following information:
- Users must not install any application or agent, to include UC soft clients, VTC software, or IM client that connects to or uses a public VoIP or IM service for non-official business.
- Users must not install any application or agent, to include UC soft clients, VTC software, or IM client that communicates peer-to-peer with other applications, agents, or personal phone gateways.
- Users must not use a USB or Ethernet subscriber line interface card (SLIC) associated with a commercial VoIP service (such as magicJack) or a personal VoIP system in the DoD unless the SLIC is sanctioned and provided by a DoD component or organization.
- Users must not use UC soft client accessories capable of bridging a DoD network or DoD application with another computer, phone network, or the PSTN.
- Users must not use DoD-provided UC soft client while working in their normal DoD workspace without permission of the ISSO. 
- Users must receive a caution notice discussing the non-assured nature of UC soft client applications for C2 user awareness that for assured service a UC soft client should not be the primary method of communications.
- Users must receive instruction for the proper and safe use of webcams or built-in cameras when used in a classified environment to prevent viewing classified work or classified material over non-secure networks.
- Users must receive instruction for the proper and safe use of speakerphones or built-in microphones when used in a classified environment to prevent hearing classified discussions over non-secure networks. 
- Users must receive instruction regarding the proper and safe use of presentation, document, and desktop sharing.

Sites may modify the above items in accordance with local site policy. However, each item must be addressed in the user agreement. A user agreement may be a standalone document or a larger document addressing remote access or workstation use that enforces the acceptable use of UC soft client applications and accessories.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17133r3_chk'
  tag severity: 'medium'
  tag gid: 'V-16090'
  tag rid: 'SV-17078r3_rule'
  tag stig_id: 'VVoIP 1335'
  tag gtitle: 'Enforce UC soft client acceptable use'
  tag fix_id: 'F-16195r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
