control 'SV-24780' do
  title 'DBMS account passwords should be set to expire every 60 days or more frequently.'
  desc 'The PASSWORD_LIFE_TIME value specifies the length of time the same password may be used to authenticate to a database account. After the time period specified has passed for the assigned password, the user is required to change their password or else forfeit access to the database. Frequent password changes help to decrease the likelihood or duration of a password compromise that would result in unauthorized access.'
  desc 'check', "NOTE: Use of authentication via certificate or CAC for Oracle accounts makes the accounts non-interactive for the purposes of this check.

The DEFAULT profile is required to have a password lifetime set not to exceed 60 days, which is the current password lifetime limit per DoD policy.

Custom profiles for non-interactive accounts (accounts used by applications or other systems) may have PASSWORD_LIFE_TIME set to a time greater than 60 days, but must still have a limit assigned.

Limits of one year or less for non-interactive accounts require IAO authorization and should be set to a lifetime as low as administration and operation of the application will support.

From SQL*Plus:

  select profile, limit
  from dba_profiles,
  (select limit as def_pwd_life_tm
   from dba_profiles 
   where profile = 'DEFAULT'
   and resource_name = 'PASSWORD_LIFE_TIME')
  where resource_name = 'PASSWORD_LIFE_TIME'
  and ((replace(limit, 'DEFAULT', def_pwd_life_tm) in
  ('UNLIMITED', NULL))
  or (lpad(replace(limit, 'DEFAULT', def_pwd_life_tm),40,'0') >
  lpad('60',40,'0')));

If the DEFAULT profile has a value greater than 60 days, this is a Finding.

If any non-default profiles have password lifetimes greater than 60 days and are assigned to interactive accounts, this is a Finding.

If any non-default profiles have password lifetimes greater than 365 days (1 year) and are assigned to any accounts, this is a Finding.

If any profiles have PASSWORD_LIFE_TIME set to UNLIMITED, NULL or no value, this is a Finding.

Verify in the System Security Plan that all accounts assigned to profiles with a password lifetime greater than 60 days belong to non-interactive accounts."
  desc 'fix', 'Assign a password lifetime of 60 days or less to the default database profile.

Assign a password lifetime of 60 days or less to non-default profiles assigned to interactive database accounts.

Assign as password lifetime of 365 days or less to non-default profiles assigned to non-interactive database accounts that do not support frequent password changes.

Include a list of all database accounts and their profile assignments in the System Security Plan.

Modify profiles to assign a password lifetime.

From SQL*Plus:
  alter profile default limit password_life_time 60;
  alter profile [profile name] limit password_life_time [60 to 365];

Replace [profile name] with any existing, non-default profile name and [60 to 365] with a value between 60 and 365 (days) inclusive.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29356r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15153'
  tag rid: 'SV-24780r2_rule'
  tag stig_id: 'DG0125-ORACLE11'
  tag gtitle: 'DBMS account password expiration'
  tag fix_id: 'F-26382r1_fix'
  tag responsibility: 'Database Administrator'
end
