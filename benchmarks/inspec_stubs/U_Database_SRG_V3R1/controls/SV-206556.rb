control 'SV-206556' do
  title 'If passwords are used for authentication, the DBMS must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.'
  desc 'check', 'Review the list of DBMS database objects, database configuration files, associated scripts, and applications defined within and external to the DBMS that access the database. The list should also include files or settings used to configure the operational environment for the DBMS and for interactive DBMS user accounts.

Determine whether any DBMS database objects, database configuration files, associated scripts, applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings contain database passwords. If any do, confirm that DBMS passwords stored internally or externally to the DBMS are hashed using FIPS-approved cryptographic algorithms and include a salt. If any passwords are stored in clear text, this is a finding.   If any passwords are stored with reversible encryption, this is a finding.  If any passwords are stored using unsalted hashes, this is a finding.'
  desc 'fix', 'Develop, document, and maintain a list of DBMS database objects, database configuration files, associated scripts, applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings in the System Security Plan.

Record whether they do or do not contain DBMS passwords. If passwords are present, ensure that they are correctly hashed using one-way, salted hashing functions, and that the hashes are protected by host system security.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6816r291336_chk'
  tag severity: 'medium'
  tag gid: 'V-206556'
  tag rid: 'SV-206556r617447_rule'
  tag stig_id: 'SRG-APP-000171-DB-000074'
  tag gtitle: 'SRG-APP-000171'
  tag fix_id: 'F-6816r291337_fix'
  tag 'documentable'
  tag legacy: ['SV-42805', 'V-32468']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
