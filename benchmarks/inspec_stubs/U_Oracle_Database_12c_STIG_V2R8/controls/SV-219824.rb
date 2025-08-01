control 'SV-219824' do
  title 'Access to default accounts used to support replication must be restricted to authorized DBAs.'
  desc 'Replication database accounts are used for database connections between databases. Replication requires the configuration of these accounts using the same username and password on all databases participating in the replication. Replication connections use fixed user database links. This means that access to the replication account on one server provides access to the other servers participating in the replication. Granting unauthorized access to the replication account provides unauthorized and privileged access to all databases participating in the replication group.'
  desc 'check', "From SQL*Plus:

  select 'The number of replication objects defined is: '||
  count(*) from all_tables 
  where table_name like 'REPCAT%';

If the count returned is 0, then Oracle Replication is not installed and this check is not a finding.

Otherwise:

From SQL*Plus:

  select count(*) from sys.dba_repcatlog;

If the count returned is 0, then Oracle Replication is not in use and this check is not a finding.

If any results are returned, ask the ISSO or DBA if the replication account (the default is REPADMIN, but may be customized) is restricted to ISSO-authorized personnel only.

If it is not, this is a finding.

If there are multiple replication accounts, confirm that all are justified and documented with the ISSO.

If they are not, this is a finding.

Note: Oracle Database Advanced Replication is deprecated in Oracle Database 12c. Use Oracle GoldenGate to replace all features of Advanced Replication, including multimaster replication, updatable materialized views, hierarchical materialized views, and deployment templates."
  desc 'fix', 'Change the password for default and custom replication accounts and provide the password to ISSO-authorized users only.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21535r533011_chk'
  tag severity: 'medium'
  tag gid: 'V-219824'
  tag rid: 'SV-219824r879887_rule'
  tag stig_id: 'O121-BP-021200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21534r533012_fix'
  tag 'documentable'
  tag legacy: ['SV-75901', 'V-61411']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
