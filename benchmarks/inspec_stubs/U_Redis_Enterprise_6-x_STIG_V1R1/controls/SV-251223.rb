control 'SV-251223' do
  title 'If passwords are used for authentication, Redis Enterprise DBMS must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.'
  desc 'check', 'Redis stores and displays its user passwords in encrypted form, it also and transmits passwords as one-way hashed representations utilizing SHA256. Nevertheless, any User ID and Password stores should be verified by interviewing the DBA.

Interview the DBA or ISSO and review any associated scripts, and applications defined within or external to the DBMS that access the database. The list must also include files, tables, or settings used to configure the operational environment for the DBMS and for interactive DBMS user accounts. Determine if any files contain database passwords. If any do, confirm that DBMS passwords stored internally or externally to the DBMS are encoded or encrypted.

If any passwords are stored in clear text, this is a finding.

Ask the DBA/System Administrator (SA)/Application Support staff if they have created an external password store for applications, batch jobs, and scripts to use on the database server. Verify that all passwords stored there are encrypted.

If a password store is used and any password is not encrypted, this is a finding.'
  desc 'fix', 'Develop, document, and maintain a list of DBMS database objects, database configuration files, associated scripts, applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings in the System Security Plan.

Record whether they do or do not contain DBMS passwords. If passwords are present, ensure that they are correctly hashed using one-way, salted hashing functions, and that the hashes are protected by host system security.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54658r804857_chk'
  tag severity: 'medium'
  tag gid: 'V-251223'
  tag rid: 'SV-251223r804859_rule'
  tag stig_id: 'RD6X-00-008800'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-54612r804858_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
