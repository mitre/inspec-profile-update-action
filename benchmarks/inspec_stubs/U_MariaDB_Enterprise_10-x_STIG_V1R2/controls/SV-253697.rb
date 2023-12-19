control 'SV-253697' do
  title 'If passwords are used for authentication, MariaDB must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the MariaDB.'
  desc 'check', 'MariaDB stores passwords encrypted. When querying users, the passwords are displayed encrypted. 

However, third-party applications, scripts, etc., might be storing passwords. In such cases, it is important to ensure these passwords are encrypted. Check all third-party applications, scripts, etc., which connect to the database and verify the passwords are encrypted. If any passwords are found in clear text, this is a finding.'
  desc 'fix', 'Document all applications, scripts, etc., which connect to the database server. Ensure passwords, if stored, are encrypted and secure.'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57149r841614_chk'
  tag severity: 'high'
  tag gid: 'V-253697'
  tag rid: 'SV-253697r841616_rule'
  tag stig_id: 'MADB-10-003800'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-57100r841615_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
