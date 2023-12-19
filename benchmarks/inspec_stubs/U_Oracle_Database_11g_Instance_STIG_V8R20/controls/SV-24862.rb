control 'SV-24862' do
  title 'Access to default accounts used to support replication should be restricted to authorized DBAs.'
  desc 'Replication database accounts are used for database connections between databases. Replication requires the configuration of these accounts using the same username and password on all databases participating in the replication. Replication connections use fixed user database links. This means that access to the replication account on one server provides access to the other servers participating in the replication. Granting unauthorized access to the replication account provides unauthorized and privileged access to all databases participating in the replication group.'
  desc 'check', "From SQL*Plus:

  select 'The number of replication objects defined is: '||
  count(*) from all_tables 
  where table_name like 'REPCAT%';

If the count returned is 0, then Oracle Replication is not installed and this check is Not a Finding.

Otherwise:

From SQL*Plus:

  select count(*) from sys.dba_repcatlog;

If the count returned is 0, then Oracle Replication is not in use and this check is Not a Finding.

If any results are returned, ask the IAO or DBA if the replication account (the default is REPADMIN, but may be customized) is restricted to IAO-authorized personnel only.

If it is not, this is a Finding.

If there are multiple replication accounts, confirm that all are justified and documented with the IAO.

If they are not, this is a Finding."
  desc 'fix', 'Change the password for default and custom replication accounts and provide the password to IAO-authorized users only.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29420r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2516'
  tag rid: 'SV-24862r1_rule'
  tag stig_id: 'DO0210-ORACLE11'
  tag gtitle: 'Oracle shared replication account access'
  tag fix_id: 'F-26447r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
