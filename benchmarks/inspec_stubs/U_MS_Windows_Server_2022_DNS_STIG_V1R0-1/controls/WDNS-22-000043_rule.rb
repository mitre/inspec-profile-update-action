control 'WDNS-22-000043_rule' do
  title 'The Windows 2022 DNS Server must implement a local cache of revocation data for PKI authentication.'
  desc 'Not configuring a local cache of revocation data could allow access to users who are no longer authorized (users with revoked certificates).

SIG(0) is used for server-to-server authentication for DNS transactions, and it uses PKI-based authentication. In cases where SIG(0) is being used instead of TSIG (which uses a shared key, not PKI-based authentication), this requirement is applicable.'
  desc 'check', 'Consult with the system administrator to determine if a third-party CRL server is being used for certificate revocation lookup.

If there is, determine if a documented procedure is in place to store a copy of the CRL locally (local to the site, as an alternative to querying the actual Certificate Authorities). An example would be an OCSP responder installed at the local site.

If there is no local cache of revocation data, this is a finding.'
  desc 'fix', 'Configure local revocation data to be used in the event access to Certificate Authorities is hindered.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000043_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000043'
  tag rid: 'WDNS-22-000043_rule'
  tag stig_id: 'WDNS-22-000043'
  tag gtitle: 'SRG-APP-000401-DNS-000051'
  tag fix_id: 'F-WDNS-22-000043_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
