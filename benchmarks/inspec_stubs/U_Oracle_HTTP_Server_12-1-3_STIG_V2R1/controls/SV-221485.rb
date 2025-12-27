control 'SV-221485' do
  title 'OHS must be integrated with a tool such as Oracle Access Manager to enforce a client-side certificate revocation check through the OCSP protocol.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', '1. Check to see if a product such as Oracle Access Manager that could be used for authentication, could also provide OCSP validation.

2. If not, this is a finding.'
  desc 'fix', '1. Use a product such as Oracle Access Manager for authentication.

2.  Implement OCSP validation within that product.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23200r415138_chk'
  tag severity: 'medium'
  tag gid: 'V-221485'
  tag rid: 'SV-221485r415140_rule'
  tag stig_id: 'OH12-1X-000251'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-23189r415139_fix'
  tag 'documentable'
  tag legacy: ['SV-78919', 'V-64429']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
