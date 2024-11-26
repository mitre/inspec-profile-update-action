control 'SV-24604' do
  title 'Default demonstration and sample database objects and applications should be removed.'
  desc 'Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', "From SQL*Plus:
      select username from dba_users where username in
      ('ALLUSERS', 'AOLDEMO', 'AQDEMO', 'AQJAVA', 'AQUSER',
       'AUC_GUEST', 'BI', 'CTXDEMO', 'DEMO8', 'DEV2000_DEMOS',
       'HR', 'IX', 'OE', 'ORABAMSAMPLES', 'PM', 'PORTAL_DEMO',
       'PORTAL30_DEMO', 'QS', 'SCOTT', 'SECDEMO', 'SH',
       'WK_TEST')
      or username like 'QS_%';

If any usernames are listed and are not documented in the System Security Plan and authorized by the IAO, this is a Finding.

See MetaLink note 160861.1 for a list of Oracle database users and usages."
  desc 'fix', 'For the sample applications and schemas with the Oracle database installation, use the provided SQL scripts (if present) to remove the application objects and drop the demo users and schemas:

From SQL*Plus:
  -- Human Resources application: 
  @?/demo/schema/human_resources.hr_drop.sql
  -- Order Entry application: 
  @?/demo/schema/order_entry/oe_drop.sql and oc_drop.sql
  -- Product Media application:  
  @?/demo/schema/product_media/pm_drop.sql
  -- Information Exchange application:
  @?/demo/schema/information_exchange/ix_drop.sql
  -- Sales History application:
  @?/demo/schema/sales_history/sh_drop.sql

For other demo applications, deinstall using the SQL command:
  drop user [demo username] cascade;'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1099r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15609'
  tag rid: 'SV-24604r2_rule'
  tag stig_id: 'DG0014-ORACLE11'
  tag gtitle: 'DBMS demonstration and sample databases'
  tag fix_id: 'F-17990r1_fix'
  tag responsibility: 'Database Administrator'
end
