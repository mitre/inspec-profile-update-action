control 'SV-214137' do
  title 'PostgreSQL must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability.

This requirement focuses on communications protection for PostgreSQL session rather than for the network packet.'
  desc 'check', 'As the database administrator (shown here as "postgres"), verify the following setting in postgresql.conf:

$ sudo su - postgres
$ psql -c "SHOW ssl_ca_file"
$ psql -c "SHOW ssl_cert_file"

If the database is not configured to used approved certificates, this is a finding.'
  desc 'fix', "Revoke trust in any certificates not issued by a DoD-approved certificate authority.

Configure PostgreSQL to accept only DoD and DoD-approved PKI end-entity certificates.

To configure PostgreSQL to accept approved CA's, see the official PostgreSQL documentation: http://www.postgresql.org/docs/current/static/ssl-tcp.html

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15353r361042_chk'
  tag severity: 'medium'
  tag gid: 'V-214137'
  tag rid: 'SV-214137r508027_rule'
  tag stig_id: 'PGS9-00-010300'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-15351r361043_fix'
  tag 'documentable'
  tag legacy: ['SV-87683', 'V-73031']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
