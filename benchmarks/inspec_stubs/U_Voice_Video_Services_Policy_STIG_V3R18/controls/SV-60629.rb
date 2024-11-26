control 'SV-60629' do
  title 'Unencrypted and unsigned VVoIP endpoint configuration files traversing the DISN must be protected within a VPN between enclaves.'
  desc 'When VVoIP configuration files traverse a network in an unencrypted state, system information may be used by an adversary, which in the aggregate, may reveal sensitive data. When VVoIP traffic is passed in the clear it is open to sniffing attacks. This vulnerability exists whether the traffic is on a LAN or a WAN. Unencrypted and unsigned configuration files must be wrapped within an encrypted VPN to mitigate this risk.

DoD-to-DoD voice communications are generally considered to contain sensitive information. Local DoD enclaves connect to a DISN SDN via an access circuit. Unless the site is a host to a SDN, or close enough to it to be served by DoD owned facilities, some portion of the access circuit will utilize leased commercial facilities. Additionally, the DISN core network itself may traverse commercial services and facilities. Therefore, DoD voice and data traffic crossing the unclassified DISN must be encrypted.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement:
Verify VVoIP endpoint configuration files traversing the DISN must be protected within a VPN secured using FIPS 140-2 or NSA approved encryption between enclaves. The reviewer may downgrade to CAT 3 when vendor provided PKI or x.509 certs are used rather than DoD PKI certificates.

NOTE: This requirement is not applicable to systems that use Cisco TFTP.'
  desc 'fix', 'Configure the VVoIP endpoint configuration files traversing the DISN to be protected within a VPN secured using FIPS 140-2 or NSA approved encryption between enclaves.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-50235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-47753'
  tag rid: 'SV-60629r1_rule'
  tag stig_id: 'VVoIP 1415 (GENERAL)'
  tag gtitle: 'VVoIP 1415'
  tag fix_id: 'F-51379r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
