control 'SV-24393' do
  title 'Sensitive data should be labeled.'
  desc 'The sensitivity marking or labeling of data items promotes the correct handling and protection of the data. Without such notification, the user may unwittingly disclose sensitive data to unauthorized users.'
  desc 'check', 'If database does not contain sensitive data, this check is Not a Finding.

If Oracle Label Security is not installed and database contains sensitive data, this is a Finding.

From SQL*Plus:
  select * from DBA_SA_USERS;

Compare results to the requirements for labeling as specified in the System Security Plan.

If label security is not configured as specified in the System Security Plan, this is a Finding.'
  desc 'fix', 'Develop, document and implement label security requirements.

Install and configure label security in accordance with the System Security Plan.

Monitor and audit changes to the label security configuration.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-17063r2_chk'
  tag severity: 'low'
  tag gid: 'V-15616'
  tag rid: 'SV-24393r2_rule'
  tag stig_id: 'DG0087-ORACLE11'
  tag gtitle: 'DBMS sensitive data labeling'
  tag fix_id: 'F-2587r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
