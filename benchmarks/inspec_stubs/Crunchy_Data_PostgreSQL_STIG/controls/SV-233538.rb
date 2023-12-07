control 'SV-233538' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, PostgreSQL, associated applications, and infrastructure must leverage protection mechanisms.

PostgreSQL uses OpenSSL SSLv23_method() in fe-secure-openssl.c; while the name is misleading, this function enables only TLS encryption methods, not SSL.

See OpenSSL: https://mta.openssl.org/pipermail/openssl-dev/2015-May/001449.html'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

As the database administrator (shown here as "postgres"), verify SSL is enabled in postgresql.conf by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl" 

If SSL is off, this is a finding.

If PostgreSQL, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding.'
  desc 'fix', 'Implement protective measures against unauthorized disclosure and modification during reception.

To configure PostgreSQL to use SSL, see supplementary content APPENDIX-G for instructions on enabling SSL.'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36732r606837_chk'
  tag severity: 'medium'
  tag gid: 'V-233538'
  tag rid: 'SV-233538r606839_rule'
  tag stig_id: 'CD12-00-003000'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-36697r606838_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
