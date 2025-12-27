control 'SV-224167' do
  title 'If passwords are used for authentication, the EDB Postgres Advanced Server must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.

In Postgres, encrypted passwords may be generated and stored using either MD5 or SRAM-SHA-256 encryption algorithms. The Postgres password_encryption parameter identifies which algorithm is being used by the Postgres cluster (i.e., instance). In general, MD5 is not approved for use within DoD systems. However, SCRAM-SHA-256 is approved for use within the DoD.'
  desc 'check', 'Execute the following SQL as enterprisedb:

 SHOW password_encryption;

If the value returned for the password_encryption parameter is not "scram-sha-256", this is a finding unless otherwise documented as approved for the system.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

 ALTER SYSTEM SET password_encryption = "scram-sha-256";
 SELECT pg_reload_conf();'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25840r495519_chk'
  tag severity: 'medium'
  tag gid: 'V-224167'
  tag rid: 'SV-224167r508023_rule'
  tag stig_id: 'EP11-00-004300'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-25828r495520_fix'
  tag 'documentable'
  tag legacy: ['V-100361', 'SV-109465']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
