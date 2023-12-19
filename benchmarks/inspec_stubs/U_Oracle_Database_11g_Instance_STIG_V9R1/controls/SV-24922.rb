control 'SV-24922' do
  title 'The Oracle REMOTE_LOGIN_PASSWORDFILE parameter should be set to EXCLUSIVE or NONE.'
  desc 'The REMOTE_LOGIN_PASSWORDFILE setting of "NONE" disallows remote administration of the database. The REMOTE_LOGIN_PASSWORDFILE setting of "EXCLUSIVE" allows for auditing of individual DBA logins to the SYS account. If not set to "EXCLUSIVE", remote connections to the database as "internal" or "as SYSDBA" are not logged to an individual account.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'remote_login_passwordfile';

If the value returned does not equal 'EXCLUSIVE' or 'NONE', this is a Finding."
  desc 'fix', "Disable use of the remote_login_passwordfile where remote administration is not authorized by specifying a value of NONE.

If authorized, restrict use of a password file to exclusive use by each database by specifying a value of EXCLUSIVE.

From SQL*Plus:

  alter system set remote_login_passwordfile = 'EXCLUSIVE' scope = spfile;

  OR

  alter system set remote_login_passwordfile = 'NONE' scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup."
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29473r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2558'
  tag rid: 'SV-24922r2_rule'
  tag stig_id: 'DO3546-ORACLE11'
  tag gtitle: 'Oracle REMOTE_LOGIN_PASSWORDFILE parameter'
  tag fix_id: 'F-26537r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
