control 'SV-215608' do
  title 'The Windows 2012 DNS Server must implement a local cache of revocation data for PKIauthentication in the event revocation information via the network is not accessible.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

SIG(0) is used for server-to-server authentication for DNS transactions, and it uses PKI-based authentication. So, in cases where SIG(0) is being used instead of TSIG (which uses a shared key, not PKI-based authentication), this requirement is applicable.'
  desc 'check', 'Consult with the SA to determine if there is a third-party CRL server being used for certificate revocation lookup.

If there is, verify if a documented procedure is in place to store a copy of the CRL locally (local to the site, as an alternative to querying the actual Certificate Authorities). An example would be an OCSP responder installed at the local site.

If there is no local cache of revocation data, this is a finding.'
  desc 'fix', 'Configure local revocation data to be used in the event access to Certificate Authorities is hindered.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16802r314299_chk'
  tag severity: 'medium'
  tag gid: 'V-215608'
  tag rid: 'SV-215608r561297_rule'
  tag stig_id: 'WDNS-IA-000011'
  tag gtitle: 'SRG-APP-000401-DNS-000051'
  tag fix_id: 'F-16800r314300_fix'
  tag 'documentable'
  tag legacy: ['SV-73079', 'V-58649']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
