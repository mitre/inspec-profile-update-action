control 'SV-220321' do
  title 'PostgreSQL must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of PostgreSQL with the encryption devices.'
  desc 'check', 'If PostgreSQL is deployed in an unclassified environment, this is not applicable (NA).

If PostgreSQL is not using NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, this is a finding.

To check if PostgreSQL is configured to use SSL, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If SSL is off, this is a finding.

Consult network administration staff to determine whether the server is protected by NSA-approved encrypting devices. If not, this a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure PostgreSQL to use SSL, as a database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameter: 

ssl = on 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload 

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G. 

Deploy NSA-approved encrypting devices to protect the server on the network.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-22036r392699_chk'
  tag severity: 'medium'
  tag gid: 'V-220321'
  tag rid: 'SV-220321r508027_rule'
  tag stig_id: 'PGS9-00-008100'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag fix_id: 'F-22026r392700_fix'
  tag 'documentable'
  tag legacy: ['SV-87643', 'V-72991']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
