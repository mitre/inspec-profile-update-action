control 'SV-24937' do
  title 'The Oracle O7_DICTIONARY_ACCESSIBILITY parameter should be set to FALSE.'
  desc 'The database data dictionary tables contain the data used by the database for database functions including database authentication and authorization as well as database configuration and control. By default, the parameter O7_DICTIONARY_ACCESSIBILITY is set to FALSE to prevent accounts with the privilege SELECT ANY TABLE from selecting the data dictionary tables. This setting protects the data dictionary from unintended access authorization by requiring full system privileges or direct table access permissions.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'O7_dictionary_accessibility';

If the value returned is TRUE, this is a Finding.

If the parameter does not exist or the value returned is FALSE, this is Not a Finding."
  desc 'fix', 'Disable O7_dictionary_accessibility to restrict access to system tables to users granted privileges to access objects owned by all users.

From SQL*Plus:

  alter system set O7_dictionary_accessibility = FALSE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29483r2_chk'
  tag severity: 'low'
  tag gid: 'V-2586'
  tag rid: 'SV-24937r2_rule'
  tag stig_id: 'DO3685-ORACLE11'
  tag gtitle: 'Oracle O7_DICTIONARY_ACCESSIBILITY parameter'
  tag fix_id: 'F-26549r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
