control 'SV-233586' do
  title 'PostgreSQL must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', %q(If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

One possible way to encrypt data within PostgreSQL is to use the pgcrypto extension.

To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as "postgres"), run the following command:

$ sudo su - postgres
$ psql -c "SELECT * FROM pg_available_extensions where name='pgcrypto'"

If data in the database requires encryption and pgcrypto is not available, this is a finding.

If disk or filesystem requires encryption, ask the system owner, database administrator (DBA), and system administrator (SA) to demonstrate the use of disk-level encryption. If this is required and is not found, this is a finding.

If controls do not exist or are not enabled, this is a finding.)
  desc 'fix', "Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.

The pgcrypto module provides cryptographic functions for PostgreSQL. See supplementary content APPENDIX-E for documentation on installing pgcrypto.

With pgcrypto installed, it is possible to insert encrypted data into the database:

INSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('xdes')));"
  impact 0.7
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36780r606981_chk'
  tag severity: 'high'
  tag gid: 'V-233586'
  tag rid: 'SV-233586r836825_rule'
  tag stig_id: 'CD12-00-008300'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-36745r606982_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
