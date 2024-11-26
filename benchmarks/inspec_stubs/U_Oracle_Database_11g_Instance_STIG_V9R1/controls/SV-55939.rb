control 'SV-55939' do
  title 'The Oracle SEC_MAX_FAILED_LOGIN_ATTEMPTS parameter should be set to an ISSO-approved value between 1 and 3.'
  desc 'The SEC_MAX_FAILED_LOGIN_ATTEMPTS prevents multiple failed login attempts by a single connection. The parameter differs from the limit set on user profiles and applied to failed login attempts to a single user account. Limiting failed authentication attempts by a single connection helps protect against Denial of Service (DoS) attacks and authentication attempts against multiple user accounts.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'sec_max_failed_login_attempts';

If the value returned is equal to 0 or greater than 3, this is a Finding."
  desc 'fix', 'Limit the number of failed login attempts for the database.

From SQL*Plus:

 alter system set sec_max_failed_login_attempts = 3 scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-16815r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16035'
  tag rid: 'SV-55939r2_rule'
  tag stig_id: 'DO6749-ORACLE11'
  tag gtitle: 'Oracle SEC_MAX_FAILED_LOGIN_ATTEMPTS parameter'
  tag fix_id: 'F-16078r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
