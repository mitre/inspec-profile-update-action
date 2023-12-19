control 'SV-24919' do
  title 'The Oracle SQL92_SECURITY parameter should be set to TRUE.'
  desc 'The configuration option SQL92_SECURITY specifies whether table-level SELECT privileges are required to execute an update or delete that references table column values. If this option is disabled (set to FALSE), the UPDATE privilege can be used to determine values that should require SELECT privileges.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'sql92_security';

If the value returned is set to FALSE, this is a Finding.

If the parameter is set to TRUE or does not exist, this is Not a Finding."
  desc 'fix', 'Enable SQL92 security.

From SQL*Plus:

  alter system set sql92_security = TRUE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29471r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2556'
  tag rid: 'SV-24919r2_rule'
  tag stig_id: 'DO3540-ORACLE11'
  tag gtitle: 'Oracle SQL92_SECURITY parameter'
  tag fix_id: 'F-26535r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
