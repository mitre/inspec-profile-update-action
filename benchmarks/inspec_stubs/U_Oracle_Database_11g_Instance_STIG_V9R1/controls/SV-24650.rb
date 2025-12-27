control 'SV-24650' do
  title 'Database accounts should not specify account lock times less than the site-approved minimum.'
  desc 'The FAILED_LOGIN_ATTEMPTS value limits the number of failed login attempts allowed before an account is locked. Setting this value limits the ability of unauthorized users to guess passwords and alerts the DBA when password guessing has occurred (accounts display as locked). For non-interactive accounts, the number of failed logins should be set to an IAO-approved value.'
  desc 'check', "From SQL*Plus:
  select profile||': '||limit from dba_profiles,
  (select limit as def_login_attempts from dba_profiles 
   where profile = 'DEFAULT'
   and resource_name = 'FAILED_LOGIN_ATTEMPTS')
  where resource_name = 'FAILED_LOGIN_ATTEMPTS'    
  and replace(limit, 'DEFAULT', def_login_attempts) IN
  ('UNLIMITED', NULL)
  or resource_name = 'FAILED_LOGIN_ATTEMPTS'
  and to_number(decode(limit, 'UNLIMITED', 10, 'DEFAULT', 10, limit)) > 3;

If the DEFAULT profile is returned with a limit not less than or equal to 3, this is a Finding.

If any non-DEFAULT profiles are returned with limits not documented and approved by the IAO, this is a Finding.

NOTE:  If the limit 'DEFAULT' is returned for any non-DEFAULT profiles, the profile limit is set to the corresponding value in the DEFAULT profile. If the DEFAULT profile is a Finding, so is the profile that references it."
  desc 'fix', 'Modify profiles to meet the failed login attempt requirement limit.

From SQL*Plus:
  alter profile default limit
  failed_login_attempts 3;

  alter profile [profile name] limit
  failed_login_attempts [IAO-approved value];

Replace [profile name] with any existing, non-default profile names.

Document in the System Security Plan all profiles and settings.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29174r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3817'
  tag rid: 'SV-24650r2_rule'
  tag stig_id: 'DG0073-ORACLE11'
  tag gtitle: 'DBMS failed login account lock'
  tag fix_id: 'F-2561r1_fix'
  tag responsibility: 'Database Administrator'
end
