control 'SRG-NET-000371-VVEP-00037_rule' do
  title 'The Unified Communications Endpoint must be configured to use FIPS compliant algorithms for network traffic.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered. TLS can be used to secure SIP and SCCP signaling by configuring the session manager in a secure mode.

DOD-to-DOD voice communications are generally considered to contain sensitive information and therefore DOD voice and data traffic crossing the unclassified DISN must be encrypted. Cryptographic mechanisms such as Media Access Control Security (MACsec) implemented to protect information include cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the Unified Communications Endpoint uses encryption for network traffic. 

If the Unified Communications Endpoint does not use encryption for network traffic, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to use encryption for network traffic.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000371-VVEP-00037_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000371-VVEP-00037'
  tag rid: 'SRG-NET-000371-VVEP-00037_rule'
  tag stig_id: 'SRG-NET-000371-VVEP-00037'
  tag gtitle: 'SRG-NET-000371-VVEP-00037'
  tag fix_id: 'F-SRG-NET-000371-VVEP-00037_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
