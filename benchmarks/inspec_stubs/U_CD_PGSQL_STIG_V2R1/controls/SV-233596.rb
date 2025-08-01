control 'SV-233596' do
  title 'If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires Authorizing Official (AO) approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to PostgreSQL.'
  desc 'check', %q(Note: The following instructions use the PGVER environment variables. See supplementary content APPENDIX-H for PGVER.

To check if password encryption is enabled, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW password_encryption"

If password_encryption is not "scram-sha-256", this is a finding.

Next, to identify if any passwords have been stored without being hashed and salted, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -x -c "SELECT usename, passwd FROM pg_shadow WHERE passwd IS NULL AND passwd NOT LIKE 'SCRAM-SHA-256%';"

If any password is in plaintext, this is a finding.)
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To enable password_encryption, as the database administrator, edit postgresql.conf:


$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
password_encryption = 'scram-sha-256'

Institute a policy of not using the "WITH UNENCRYPTED PASSWORD" option with the CREATE ROLE/USER and ALTER ROLE/USER commands. (This option overrides the setting of the password_encryption configuration parameter).

As the system administrator, restart the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl restart postgresql-${PGVER?})
  impact 0.7
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36790r607011_chk'
  tag severity: 'high'
  tag gid: 'V-233596'
  tag rid: 'SV-233596r836826_rule'
  tag stig_id: 'CD12-00-009500'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-36755r607012_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
