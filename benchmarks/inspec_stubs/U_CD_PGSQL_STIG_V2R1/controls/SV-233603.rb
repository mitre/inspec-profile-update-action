control 'SV-233603' do
  title 'PostgreSQL must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure security controls and identity vetting procedures are in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at https://cyber.mil/pki-pke/interoperability

This requirement focuses on communications protection for PostgreSQL session rather than for the network packet.'
  desc 'check', 'As the database administrator (shown here as "postgres"), verify the following setting in postgresql.conf:

$ sudo su - postgres
$ psql -c "SHOW ssl_ca_file"
$ psql -c "SHOW ssl_cert_file"

If the database is not configured to use only DOD-approved certificates, this is a finding.'
  desc 'fix', 'Revoke trust in any certificates not issued by a DoD-approved certificate authority.

Configure PostgreSQL to accept only DoD and DoD-approved PKI end-entity certificates.

To configure PostgreSQL to accept approved CAs, see the official PostgreSQL documentation: http://www.postgresql.org/docs/current/static/ssl-tcp.html

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36797r607032_chk'
  tag severity: 'medium'
  tag gid: 'V-233603'
  tag rid: 'SV-233603r617425_rule'
  tag stig_id: 'CD12-00-010300'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-36762r607033_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
