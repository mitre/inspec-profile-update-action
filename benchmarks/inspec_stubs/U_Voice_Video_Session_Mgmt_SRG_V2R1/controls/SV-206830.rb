control 'SV-206830' do
  title 'The Voice Video Session Manager must use encryption for signaling and media traffic.'
  desc 'All signaling and media traffic from a Voice Video Session Manager must be encrypted. Network elements utilizing encryption are required to use FIPS compliant mechanisms for authenticating to cryptographic modules. FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. Unapproved mechanisms used for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity and DoD data may be compromised.

Voice Video protocol suites include SIP, SCCP, and H.323. Each of these protocol suites uses different methodologies for securing transmitted signaling. The H.323 protocol suite relies on the H.235 series, which describes security within H.323, including security for both signaling and media. For SIP protocol, the DoD has created the AS-SIP protocol, which provides for implementing Transport Layer Security (TLS), Multi-Level Precedence and Preemption (MLPP), reliance on Secure Real-Time Transport Protocol (SRTP) for media streams, and Differentiated Services Code Point (DSCP) for traffic management through priority packet routing. To secure SCCP, TLS must be implemented with the protocol.'
  desc 'check', 'Verify the Voice Video Session Manager uses encryption for signaling and media traffic.

If the Voice Video Session Manager does not use encryption for signaling and media traffic, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to use encryption for signaling and media traffic.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7085r364679_chk'
  tag severity: 'high'
  tag gid: 'V-206830'
  tag rid: 'SV-206830r508661_rule'
  tag stig_id: 'SRG-NET-000168-VVSM-00016'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-7085r364680_fix'
  tag 'documentable'
  tag legacy: ['SV-76585', 'V-62095']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
