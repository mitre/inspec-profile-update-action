control 'SV-233579' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, PostgreSQL, associated applications, and infrastructure must leverage transmission protection mechanisms.

PostgreSQL uses OpenSSL SSLv23_method() in fe-secure-openssl.c, while the name is misleading, this function enables only TLS encryption methods, not SSL.

See OpenSSL: https://mta.openssl.org/pipermail/openssl-dev/2015-May/001449.html'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

As the database administrator (shown here as "postgres"), verify SSL is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If SSL is not enabled, this is a finding.

If PostgreSQL does not employ protective measures against unauthorized disclosure and modification during preparation for transmission, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Implement protective measures against unauthorized disclosure and modification during preparation for transmission.

To configure PostgreSQL to use SSL, as a database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

Next, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36773r606960_chk'
  tag severity: 'medium'
  tag gid: 'V-233579'
  tag rid: 'SV-233579r606962_rule'
  tag stig_id: 'CD12-00-007200'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-36738r606961_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
