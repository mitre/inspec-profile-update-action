control 'SV-206778' do
  title 'The Voice Video Endpoint must protect the integrity of transmitted configuration files from the Voice Video Session Manager.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered. When Voice Video Endpoint configuration files traverse a network without encryption for confidentiality, system information can be intercepted by an adversary. Encryption of the configuration files mitigates this vulnerability. However, TFTP is the most common protocol used for configuration file transfers and does not natively encrypt data. The Cisco TFTP implementation for VoIP systems uses encryption to both store and transfer configuration files. Refer to the “CISCO-UCM-TFTP” Vulnerability Analysis report provided by the Protocols, Ports, and Services management site for more details. Integrity checks during the transmission of configuration files ensure no changes have been introduced by adversarial attacks. TLS can be utilized to secure SIP and SCCP signaling by configuring the session manager in a secure mode.

DoD-to-DoD voice communications are generally considered to contain sensitive information and therefore DoD voice and data traffic crossing the unclassified DISN must be encrypted. Cryptographic mechanisms such as Media Access Control Security (MACsec) implemented to protect information integrity include cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the Voice Video Endpoint protects the integrity of transmitted configuration files from the Voice Video Session Manager. 

If the Voice Video Endpoint does not protect the integrity of transmitted configuration files from the Voice Video Session Manager, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to protect the integrity of transmitted configuration files from the Voice Video Session Manager.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7034r363857_chk'
  tag severity: 'high'
  tag gid: 'V-206778'
  tag rid: 'SV-206778r604140_rule'
  tag stig_id: 'SRG-NET-000371-VVEP-00017'
  tag gtitle: 'SRG-NET-000371'
  tag fix_id: 'F-7034r363858_fix'
  tag 'documentable'
  tag legacy: ['V-66713', 'SV-81203']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
