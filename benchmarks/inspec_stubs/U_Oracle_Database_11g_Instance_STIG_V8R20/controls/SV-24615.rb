control 'SV-24615' do
  title 'Required auditing parameters for database auditing should be set.'
  desc 'Oracle auditing can be set to log audit data to the database or operating system files. Logging events to the database prevents operating system users from viewing the data, while logging events to operating system files prevents malicious database users from accessing the data. The value NONE disables auditing and is, therefore, not in compliance with policy.'
  desc 'check', "From SQL*Plus:
  select value from v$parameter where name = 'audit_trail';

If the value returned is NONE, this is a Finding."
  desc 'fix', "Enable database auditing.

Select the desired audit trail format (external file or internal database table).  

From SQL*Plus:
  alter system set audit_trail= [audit trail format] scope=spfile;

Compliant selections for [audit trail format] are (per MetaLink Note 30690.1):

Oracle 11.1 – 11.2	= 'true', 'os' & 'db' (true = os for backward compatibility)
Oracle 11.1 – 11.2 	= 'db_extended', 'xml' & 'xml, extended'

The above SQL*Plus command will set the parameter to take effect at next system startup."
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1126r2_chk'
  tag severity: 'medium'
  tag gid: 'V-5685'
  tag rid: 'SV-24615r2_rule'
  tag stig_id: 'DG0029-ORACLE11'
  tag gtitle: 'Database auditing'
  tag fix_id: 'F-22677r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
