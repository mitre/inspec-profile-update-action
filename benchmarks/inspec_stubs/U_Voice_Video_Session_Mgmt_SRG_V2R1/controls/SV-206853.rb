control 'SV-206853' do
  title 'The Voice Video Session Manager must implement NIST FIPS-validated cryptography to generate cryptographic hashes and to protect sensitive unclassified information.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

Voice Video protocol suites include SIP, SCCP, and H.323. Each of these protocol suites uses different methodologies for securing transmitted signaling. The H.323 protocol suite relies on the H.235 series, which describes security within H.323, including security for both signaling and media. For SIP protocol, the DoD has created the AS-SIP protocol, which provides for implementing Transport Layer Security (TLS), Multi-Level Precedence and Preemption (MLPP), reliance on Secure Real-Time Transport Protocol (SRTP) for media streams, and Differentiated Services Code Point (DSCP) for traffic management through priority packet routing. To secure SCCP, TLS must be implemented with the protocol.'
  desc 'check', 'Verify the Voice Video Session Manager implements NIST FIPS-validated cryptography to generate cryptographic hashes and to protect sensitive unclassified information.

If the Voice Video Session Manager does not implements NIST FIPS-validated cryptography to generate cryptographic hashes, this is a finding.

If the Voice Video Session Manager does not implements NIST FIPS-validated cryptography to protect sensitive unclassified information, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to implement NIST FIPS-validated cryptography to generate cryptographic hashes and to protect sensitive unclassified information.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7108r364748_chk'
  tag severity: 'high'
  tag gid: 'V-206853'
  tag rid: 'SV-206853r508661_rule'
  tag stig_id: 'SRG-NET-000510-VVSM-00015'
  tag gtitle: 'SRG-NET-000510'
  tag fix_id: 'F-7108r364749_fix'
  tag 'documentable'
  tag legacy: ['SV-76627', 'V-62137']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
