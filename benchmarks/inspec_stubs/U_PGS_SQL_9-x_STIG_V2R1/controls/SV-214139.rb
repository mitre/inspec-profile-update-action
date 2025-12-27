control 'SV-214139' do
  title 'PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'PostgreSQLs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to PostgreSQL or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', %q(To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as "postgres"), run the following command:

$ sudo su - postgres
$ psql -c "SELECT * FROM pg_available_extensions where name='pgcrypto'"

If data in the database requires encryption and pgcrypto is not available, this is a finding.

If a disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of filesystem and/or disk-level encryption. If this is required and is not found, this is a finding.)
  desc 'fix', "Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection for information requiring cryptographic protection against disclosure.

Secure the premises, equipment, and media to provide the required level of physical protection.

The pgcrypto module provides cryptographic functions for PostgreSQL. See supplementary content APPENDIX-E for documentation on installing pgcrypto.

With pgcrypto installed, it is possible to insert encrypted data into the database:

INSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('md5')));"
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15355r361048_chk'
  tag severity: 'medium'
  tag gid: 'V-214139'
  tag rid: 'SV-214139r508027_rule'
  tag stig_id: 'PGS9-00-010500'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-15353r361049_fix'
  tag 'documentable'
  tag legacy: ['SV-87687', 'V-73035']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
