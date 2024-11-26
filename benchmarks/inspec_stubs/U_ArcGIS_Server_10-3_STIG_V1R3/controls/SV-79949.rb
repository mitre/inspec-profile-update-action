control 'SV-79949' do
  title 'The ArcGIS Server, when using PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used to for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', %q(Review the ArcGIS Server configuration to ensure PKI-based authenticated endpoints validate certificates by constructing a certification path. Substitute the target environment’s values for [bracketed] variables. 

1. On each GIS Server in the ArcGIS Server Site, left-shift + right-click on Internet Explorer >> Run as a different user >> log on using the "[ArcGIS Server]" account.

Within Internet Explorer, click Tools >> Internet Options.

Open the "Advanced" tab. Within the "Security" section, verify "Check for publisher's certificate revocation" is checked.

If "Check for publisher's certificate revocation" is not checked, this is a finding.

2. Within the "Security" section, verify "Check for server certificate revocation" is checked.

If "Check for server certificate revocation" is not checked, this is a finding.

Access to the "[ArcGIS Server]" account is required to perform this check.)
  desc 'fix', %q(Configure the ArcGIS Server to ensure PKI-based authenticated endpoints validate certificates by constructing a certification path. Substitute the target environment’s values for [bracketed] variables. 

On each GIS Server in the ArcGIS Server Site, left-shift + right-click on Internet Explorer >> Run as a different user >> log on using the "[ArcGIS Server]" account.

Within Internet Explorer, click Tools >> Internet Options.

Open the "Advanced" tab. Within the "Security" section, check "Check for publisher's certificate revocation".

Within the "Security" section, check "Check for server certificate revocation".

Restart the server.

Access to the "[ArcGIS Server]" account is required to make this change.)
  impact 0.5
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66041r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65459'
  tag rid: 'SV-79949r1_rule'
  tag stig_id: 'AGIS-00-000077'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-71401r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
