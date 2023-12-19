control 'SV-108707' do
  title 'Separate MySQL user accounts with limited privileges must be created within Jamf Pro EMM.'
  desc 'If separate MySQL accounts with limited privileges are not created an adversary could gain unauthorized access to the application or gain access unauthorized features which could lead to the compromise of sensitive DoD data.

SFR ID: FMT_SMF.1(2)b. / CM-6 b

'
  desc 'check', 'Verify separate MySQL user accounts with limited privileges have been created within Jamf Pro EMM.

In MySQL, execute the following command: 
show grants for username@localhost;

Verify the privileges match what is in the Jamf Knowledge Base article.

If separate MySQL user accounts with limited privileges have not been created within Jamf Pro EMM, this is a finding.'
  desc 'fix', 'Create separate MySQL user accounts with limited privileges within Jamf Pro EMM.

The procedures for creating user accounts and assigning account privileges are found in the following Jamf Knowledge Base articles:

MySQL 8.0: https://dev.mysql.com/doc/refman/8.0/en/creating-accounts.html
MySQL 5.7: https://dev.mysql.com/doc/refman/5.7/en/creating-accounts.html

Following is a list MySQL privileges that are required for different types of environments:
- For a standalone web application or the master node in clustered environments:
INSERT, SELECT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, LOCK TABLES

- For a child node in clustered environments: 
INSERT, SELECT, UPDATE, DELETE, DROP, LOCK TABLES

- To view connections from cluster nodes with different MySQL users:
PROCESS

Note: The "PROCESS" privilege requires the use of "*.*".'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98453r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99603'
  tag rid: 'SV-108707r1_rule'
  tag stig_id: 'JAMF-10-100100'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105287r1_fix'
  tag satisfies: ['SRG-APP-000516']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
