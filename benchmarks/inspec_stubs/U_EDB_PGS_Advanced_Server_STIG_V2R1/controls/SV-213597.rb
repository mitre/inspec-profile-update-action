control 'SV-213597' do
  title 'If passwords are used for authentication, the EDB Postgres Advanced Server must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW password_encryption;
 
If the value is not "on", this is a finding.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

ALTER SYSTEM SET password_encryption = on;
SELECT pg_reload_conf();'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14819r290103_chk'
  tag severity: 'medium'
  tag gid: 'V-213597'
  tag rid: 'SV-213597r508024_rule'
  tag stig_id: 'PPS9-00-004300'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-14817r290104_fix'
  tag 'documentable'
  tag legacy: ['SV-83551', 'V-68947']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
