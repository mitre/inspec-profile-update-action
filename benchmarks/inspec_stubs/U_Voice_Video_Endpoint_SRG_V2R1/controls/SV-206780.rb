control 'SV-206780' do
  title 'The Voice Video Endpoint must use encryption for signaling and media traffic.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered. TLS can be utilized to secure SIP and SCCP signaling by configuring the session manager in a secure mode.

DoD-to-DoD voice communications are generally considered to contain sensitive information and therefore DoD voice and data traffic crossing the unclassified DISN must be encrypted. Cryptographic mechanisms such as Media Access Control Security (MACsec) implemented to protect information include cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the Voice Video Endpoint uses encryption for signaling and media traffic. 

If the Voice Video Endpoint does not use encryption for signaling and media traffic, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to use encryption for signaling and media traffic.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7036r363863_chk'
  tag severity: 'high'
  tag gid: 'V-206780'
  tag rid: 'SV-206780r604140_rule'
  tag stig_id: 'SRG-NET-000371-VVEP-00037'
  tag gtitle: 'SRG-NET-000371'
  tag fix_id: 'F-7036r363864_fix'
  tag 'documentable'
  tag legacy: ['SV-81247', 'V-66757']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
