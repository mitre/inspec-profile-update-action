control 'SV-24426' do
  title 'Unlimited account lock times should be specified for locked accounts.'
  desc 'When no limit is imposed on failed logon attempts and accounts are not disabled after a set number of failed access attempts, then the DBMS account is vulnerable to sustained attack. When access attempts continue unrestricted, the likelihood of success is increased. A successful attempt results in unauthorized access to the database.'
  desc 'check', "From SQL*Plus:

  select profile, limit from dba_profiles
  where resource_name = 'PASSWORD_LOCK_TIME'
  and limit not in ('UNLIMITED', 'DEFAULT');

If any profiles are listed, this is a Finding.

A value of UNLIMITED means that the account is locked until it is manually unlocked."
  desc 'fix', 'Set the password_lock_time on all defined profiles to unlimited.

This will require the DBA manually to re-enable every locked account after the failed login limit has been reached.

From SQL*Plus:

  alter profile default limit password_lock_time unlimited;
  alter profile [profile name] limit password_lock_time default;

Replace [profile name] with an existing, non-default profile name.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29365r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15639'
  tag rid: 'SV-24426r2_rule'
  tag stig_id: 'DG0133-ORACLE11'
  tag gtitle: 'DBMS Account lock time'
  tag fix_id: 'F-26390r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
