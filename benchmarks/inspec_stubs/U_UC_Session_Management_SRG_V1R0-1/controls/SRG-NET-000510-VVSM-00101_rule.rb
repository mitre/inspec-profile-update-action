control 'SRG-NET-000510-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must implement NIST FIPS-validated cryptography for communications sessions.'
  desc 'All signaling and media traffic from a Unified Communications Session Manager must be encrypted. Network elements using encryption are required to use FIPS compliant mechanisms for authenticating to cryptographic modules. FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DOD requirements. Unapproved mechanisms used for authentication to the cryptographic module are not verified, and therefore cannot be relied on to provide confidentiality or integrity and DOD data may be compromised.

Voice Video protocol suites include SIP, SCCP, and H.323. Each of these protocol suites uses different methodologies for securing transmitted signaling. The H.323 protocol suite relies on the H.235 series, which describes security within H.323, including security for both signaling and media. For SIP protocol, the DOD has created the AS-SIP protocol, which provides for implementing Transport Layer Security (TLS), Multi-Level Precedence and Preemption (MLPP), reliance on Secure Real-Time Transport Protocol (SRTP) for media streams, and Differentiated Services Code Point (DSCP) for traffic management through priority packet routing. To secure SCCP, TLS must be implemented with the protocol.'
  desc 'check', 'Verify the Unified Communications Session Manager implements NIST FIPS-validated cryptography for communications sessions.

If the Unified Communications Session Manager does not implements NIST FIPS-validated cryptography for communications sessions, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to implement NIST FIPS-validated cryptography for communications sessions.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000510-VVSM-00101_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000510-VVSM-00101'
  tag rid: 'SRG-NET-000510-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000510-VVSM-00101'
  tag gtitle: 'SRG-NET-000510-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000510-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
