control 'SV-32954' do
  title 'The private web server must use an approved DoD certificate validation process.'
  desc 'Without the use of a certificate validation process, the site is vulnerable to accepting certificates that have expired or have been revoked.  This would allow unauthorized individuals access to the web server.  This also defeats the purpose of the multi-factor authentication provided by the PKI process.'
  desc 'check', 'The reviewer should query the ISSO, the SA, the web administrator, or developers as necessary to determine if the web server is configured to utilize an approved DoD certificate validation process.

The web administrator should be questioned to determine if a validation process is being utilized on the web server.

To validate this, the reviewer can ask the web administrator to describe the validation process being used. They should be able to identify either the use of certificate revocation lists (CRLs) or Online Certificate Status Protocol (OCSP).

If the production web server is accessible, the SA or the web administrator should be able to demonstrate the validation of good certificates and the rejection of bad certificates.

If CRLs are being used, the SA should be able to identify how often the CRL is updated and the location from which the CRL is downloaded.

If the web administrator cannot identify the type of validation process being used, this is a finding.'
  desc 'fix', 'Configure DoD Private Web Servers to conduct certificate revocation checking utilizing certificate revocation lists (CRLs) or Online Certificate Status Protocol (OCSP).'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33636r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13672'
  tag rid: 'SV-32954r2_rule'
  tag stig_id: 'WG145 A22'
  tag gtitle: 'WG145'
  tag fix_id: 'F-29277r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'IATS-1, IATS-2'
end
