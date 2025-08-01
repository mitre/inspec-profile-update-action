control 'SV-233602' do
  title 'PostgreSQL must enforce authorized access to all PKI private keys stored/utilized by PostgreSQL.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where PostgreSQL-stored private keys are used to authenticate PostgreSQL to the system's clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man-in-the-middle attacks against PostgreSQL system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

All access to the private key(s) of PostgreSQL must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of PostgreSQL's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', %q(First, as the database administrator (shown here as "postgres"), verify the following settings:

$ sudo su - postgres
$ psql -c "select name,                                                         case when setting = '' then                                                                            '<undefined>'                                                                                      when substring(setting, 1, 1) = '/' then                                                               setting                                                                                            else (select setting from pg_settings where name = 'data_directory') || '/' || setting               end as setting                                                                                     from pg_settings                                                                                     where name in ('ssl_ca_file', 'ssl_cert_file', 'ssl_crl_file', 'ssl_key_file');"

If the directory in which these files are stored is not protected, this is a finding.)
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Store all PostgreSQL PKI private keys in a FIPS 140-2-validated cryptographic module. 

Ensure access to PostgreSQL PKI private keys is restricted to only authenticated and authorized users.

PostgreSQL private key(s) can be stored in $PGDATA directory, which is only accessible by the database owner (usually postgres, DBA) user. Do not allow access to this system account to unauthorized users.

To put the keys in a different directory, as the database administrator (shown here as "postgres"), set the following settings to a protected directory:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
ssl_ca_file = "/some/protected/directory/root.crt"
ssl_crl_file = "/some/protected/directory/root.crl"
ssl_cert_file = "/some/protected/directory/server.crt"
ssl_key_file = "/some/protected/directory/server.key"

Now, as the system administrator, restart the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl restart postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.'
  impact 0.7
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36796r607029_chk'
  tag severity: 'high'
  tag gid: 'V-233602'
  tag rid: 'SV-233602r617333_rule'
  tag stig_id: 'CD12-00-010200'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-36761r607030_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
