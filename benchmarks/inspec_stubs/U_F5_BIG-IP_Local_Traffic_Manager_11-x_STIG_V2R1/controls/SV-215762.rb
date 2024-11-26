control 'SV-215762' do
  title 'The BIG-IP Core implementation must be configured to validate certificates used for TLS functions for connections to virtual servers by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'A trust anchor is an authoritative entity represented via a public key. Within a chain of trust, the top entity to be trusted is the "root certificate" or "trust anchor" such as a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted.

Deploying the ALG with TLS enabled may require the CA certificates for each proxy to be used for TLS traffic decryption/encryption. The installation of these certificates in each trusted root certificate store is used by proxied applications and browsers on each client.'
  desc 'check', 'If the BIG-IP Core does not provide intermediary services for TLS, or application protocols that use TLS (e.g., DNSSEC or HTTPS) for virtual servers, this is not applicable.

When intermediary services for TLS are provided, verify the BIG-IP Core is configured to validate certificates used for TLS functions by constructing a certification path to an accepted trust anchor.

Navigate to the BIG-IP System manager >> Local traffic >> Profiles >> SSL >> Server.

Select a FIPS-compliant profile.

Review the configuration under "Server Authentication" section.

Verify "Server Certificate" is set to "Required".

Verify "Trusted Certificate Authorities" is set to a DoD-approved CA bundle.

If the BIG-IP Core is not configured to validate certificates used for TLS functions by constructing a certification path to an accepted trust anchor, this is a finding.'
  desc 'fix', 'If intermediary services for TLS are provided, configure the BIG-IP Core to validate certificates used for TLS functions by constructing a certification path with status information to an accepted trust anchor.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16954r291099_chk'
  tag severity: 'medium'
  tag gid: 'V-215762'
  tag rid: 'SV-215762r557356_rule'
  tag stig_id: 'F5BI-LT-000083'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-16952r291100_fix'
  tag 'documentable'
  tag legacy: ['SV-74735', 'V-60305']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
