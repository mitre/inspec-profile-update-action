control 'SV-233340' do
  title 'When connecting with endpoints, Forescout must validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation. This is required for compliance with C2C Step 1.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

NAC must be configured for only Certificate Signing. The NAC must interact with TLS-compliant lookups and verification in exchange with endpoints in Extensible Authentication Protocol (EAP) transactions where TLS is supported within the EAP type.

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Use the Forescout CLI credentials to verify FIPS mode is set by running the "fstool version" command and look for the "FIPS enabled" setting. Use the Forescout Administrator UI to verify SecureConnector is set to use TLS version 1.2 or higher for Client-Server Connections.

1. Log on using the CLIAdmin credentials established upon initial configuration.
2. Verify FIPS mode by typing the command "fstool version".

To configure TLS:
1. Log on to the Forescout UI.
2. Select Tools >> Option >> HPS Inspection Engine >> SecureConnector.
3. In the Client-Server Connection, check the Minimum Supported TLS Version is set to TLS version 1.2.

If the NAC does not perform RFC 5280-compliant certification path validation for validating certificates used for TLS functions when connecting with endpoints, this is a finding.'
  desc 'fix', 'To enable FIPS mode log into the CLI account a use the "fstool fips" command. Use the Forescout Administrator UI to set SecureConnector to use TLS version 1.2 or higher for Client-Server Connections. 

To configure FIPS Mode:
1. Log on using the CLIAdmin credentials established upon initial configuration.
2. To enable FIPS mode, type "fstool fips". A prompt will be generated alerting the user FIPS 140-2 will be enabled. Type "Yes" for FIPS to accept this prompt.

To configure TLS:
1. Log on to the Forescout management tool.
2. Select Tools >> Option >> HPS Inspection Engine >> SecureConnector.
3. In the Client-Server Connection, set the Minimum Supported TLS Version to TLS version 1.2.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36535r811430_chk'
  tag severity: 'high'
  tag gid: 'V-233340'
  tag rid: 'SV-233340r811431_rule'
  tag stig_id: 'FORE-NC-000470'
  tag gtitle: 'SRG-NET-000580-NAC-002530'
  tag fix_id: 'F-36500r803495_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
