control 'SV-21492' do
  title 'VVoIP session media must be encrypted to provide end-to-end interoperable confidentiality and integrity.'
  desc 'Because vendors did not have interoperability, lacked end-to-end encryption, and did not provide assured service in support of Command and Control (C2) communications, VVoIP traffic originally was restricted to the local enclave. The DSN PMO, DISA Engineering, and Real Time Services (RTS) working group have been working to define network and system requirements to overcome the inherent obstacles in pursuit of a DISN wide interoperable assured service VVoIP or Voice Services network. 

VVoIP uses signaling protocols to set up and manage the communications session and the media transfer protocols carrying the communications. Both signaling and media protocols can be compromised when transmitted without encryption. To provide the assured service pre-emption and priority capabilities required for C2 telephone communications, DISA developed an extension to the SIP protocol called Assured Service SIP or AS-SIP. The common means of providing confidentiality and integrity for SIP signaling as well as providing session authentication is to encrypt it using TLS. The encryption algorithm, key strength, and key management processes are denied in the current version of the DoD Unified Capabilities Requirements (UCR) document available from the DISA voice Services PMO.'
  desc 'check', 'Review site documentation to confirm VVoIP session media is encrypted to provide end-to-end interoperable confidentiality and integrity. The devices within the VVoIP system that must be protected are endpoints, media gateways, session mangers (gatekeepers, session controllers, soft switches, etc.), border elements (session border controllers, routers, firewalls, etc.), and other network devices involved in the session signaling. Session media encryption meeting UCR requirements must be implemented end-to-end. 

If VVoIP session media is not encrypted to provide end-to-end interoperable confidentiality and integrity, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Implement VVoIP session media to be encrypted to provide end-to-end interoperable confidentiality and integrity. Fully document the implementation. Configure the VVoIP system components per the DoD APL IA deployment guide specific to the product being deployed.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23701r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19441'
  tag rid: 'SV-21492r3_rule'
  tag stig_id: 'VVoIP 6170'
  tag gtitle: 'VVoIP 6170'
  tag fix_id: 'F-20295r3_fix'
  tag 'documentable'
end
