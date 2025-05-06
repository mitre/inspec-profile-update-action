control 'SV-60611' do
  title 'VVoIP endpoint configuration files transferred via Cisco TFTP must be encrypted and signed using DoD PKI certificates.'
  desc 'When VVoIP configuration files traverse a network in an unencrypted state, system information may be used by an adversary, which in the aggregate, may reveal sensitive data. When VVoIP traffic is passed in the clear it is open to sniffing attacks. This vulnerability exists whether the traffic is on a LAN or a WAN. End-to-end encryption of the configuration files mitigates this vulnerability. However, TFTP does not natively encrypt data. The Cisco TFTP implementation for VoIP systems uses encryption to both store and transfer configuration files. Refer to the “CISCO-UCM-TFTP” Vulnerability Analysis report provided by the Protocols, Ports, and Services management site for more details. 

DoD-to-DoD voice communications are generally considered to contain sensitive information. Local DoD enclaves connect to a DISN SDN via an access circuit. Unless the site is a host to a SDN, or close enough to it to be served by DoD owned facilities, some portion of the access circuit will utilize leased commercial facilities. Additionally, the DISN core network itself may traverse commercial services and facilities. Therefore, DoD voice and data traffic crossing the unclassified DISN must be encrypted.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement:
Verify VVoIP endpoint configuration files transferred via Cisco TFTP are encrypted and signed using DoD PKI certificates.

NOTE: This requirement is not applicable to systems that do not use Cisco TFTP.'
  desc 'fix', 'Configure the VVoIP endpoint configuration files transferred via Cisco TFTP to be encrypted and signed using DoD PKI certificates. Refer to the “CISCO-UCM-TFTP” Vulnerability Analysis report provided by the Protocols, Ports, and Services management site for more details.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-50233r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47735'
  tag rid: 'SV-60611r1_rule'
  tag stig_id: 'VVoIP 1410 (GENERAL)'
  tag gtitle: 'VVoIP 1410'
  tag fix_id: 'F-51371r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Downgrade to CAT 3 when vendor provided PKI or x.509 certs are used instead of DoD PKI.'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
