control 'SV-24942' do
  title 'The Oracle RESOURCE_LIMIT parameter should be set to TRUE.'
  desc 'The Oracle RESOURCE_LIMIT parameter determines whether resource limits are enforced in database profiles. If Oracle resource limits are disabled, any defined profile limits will be ignored.

NOTE: This does not apply to password resources.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'resource_limit';

If the value returned is not set to TRUE, this is a Finding."
  desc 'fix', 'Enable resource limit checking on the database.

From SQL*Plus:

  alter system set resource_limit = TRUE scope = both;

The above SQL*Plus command will set the parameter to take effect immediately and permanently at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29487r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2593'
  tag rid: 'SV-24942r2_rule'
  tag stig_id: 'DO3696-ORACLE11'
  tag gtitle: 'Oracle RESOURCE_LIMIT parameter'
  tag fix_id: 'F-26553r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
