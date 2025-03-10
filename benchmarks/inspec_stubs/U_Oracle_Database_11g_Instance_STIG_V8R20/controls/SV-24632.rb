control 'SV-24632' do
  title 'All database non-interactive, n-tier connection, and shared accounts that exist should be documented and approved by the IAO.'
  desc 'Group authentication does not provide individual accountability for actions taken on the DBMS or data. Whenever a single database account is used to connect to the database, a secondary authentication method that provides individual account ability is required. This scenario most frequently occurs when an externally hosted application authenticates individual users to the application and the application uses a single account to retrieve or update database information on behalf of the individual users.'
  desc 'check', 'From SQL*Plus:
  select username from dba_users order by username;

Review the list of database account names to determine usage of all non-standard account names or account names that do not appear to be assigned to individuals.

For example, accounts named BATCHJOB, FMAPP, FMAPP-ADMIN do not have the appearance of assignment to an individual interactive user.

An account name like JDOE appears to be assigned to an individual.

Review the list of account names against those listed in the System Security Plan or authorized user list.

Consult the IAO or DBA to make a final determination on whether accounts are shared accounts or not.

If shared accounts are not documented as such and are not approved, this is a Finding.'
  desc 'fix', 'Use accounts assigned to individual users where feasible.

Design applications to provide individual accountability (audit logs) for actions performed under a single database account.

Implement other DBMS automated procedures that provide individual accountability.

Where appropriate, implement manual procedures to use manual logs and monitor entries against account usage to ensure procedures are followed.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2424'
  tag rid: 'SV-24632r1_rule'
  tag stig_id: 'DG0060-ORACLE11'
  tag gtitle: 'All database non-interactive, n-tier connection, a'
  tag fix_id: 'F-26170r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
