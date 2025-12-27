control 'SV-251225' do
  title 'Redis Enterprise DBMS, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates.

A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.

For more information refer to: https://docs.redislabs.com/latest/rs/administering/designing-production/security/"
  desc 'check', 'At this time, Redis Enterprise does not support OSCP and is partially compliant with RFC 5280. Verify that the host operating system is encrypted. 

If the host operating system is not encrypted or STIG-compliant, this is a finding.

To test, have the user log in to the database. If certificates are not being validated by performing RFC 5280-compliant certification path validation (i.e., "pop up" certificate validation), this is a finding.

If the host operating system is encrypted, run the following commands and verify that only DoD-approved PKI certificates are present and used for Redis Enterprise:
# cd /etc/opt/redislabs
# cat proxy_cert.pem

If no DoD-approved certificates are found, this is a finding.'
  desc 'fix', %q(Configure Redis Enterprise settings to meet organizationally defined requirements. 

1. Replace the RS server default certificates and key on all nodes with the CA-signed certificate and restart the proxy.

To replace certificates using the rladmin CLI, run:
rladmin cluster certificate set <cert-name> certificate_file <cert-file-name>.pem key_file <key-file-name>.pem
Where:
cert-name - The certificate name to replace:
For management UI: cm
For REST API: api
For database endpoint: proxy
For syncer: syncer
For metrics exporter: metrics_exporter
cert-file-name - The name of the certificate file
key-file-name - The name of the key file

Note: A certificate for the databases' endpoint should be assigned for the same domain as the cluster name. For example, for a cluster with the name "redislabs.com" the certificate should be for "*.redislabs.com".

2. Add the TLS client certificates in the UI including CA certificates and any intermediate certificates by chaining the certificate into one file (can use a cat command to chain the certificates).

3. On the client side, make sure to import and trust the CA and intermediate certificates (CA certificates can be chained with intermediate as one file to use and import).)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54660r804863_chk'
  tag severity: 'medium'
  tag gid: 'V-251225'
  tag rid: 'SV-251225r804865_rule'
  tag stig_id: 'RD6X-00-009100'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-54614r804864_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
