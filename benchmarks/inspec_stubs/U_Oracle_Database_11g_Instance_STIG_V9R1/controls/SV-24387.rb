control 'SV-24387' do
  title 'New passwords must be required to differ from old passwords by more than four characters.'
  desc 'Changing passwords frequently can thwart password-guessing attempts or re-establish protection of a compromised DBMS account. Minor changes to passwords may not accomplish this as password guessing may be able to continue to build on previous guesses or the new password may be easily guessed using the old password.'
  desc 'check', "If no DBMS accounts authenticate using passwords, this check is Not a Finding.  

Confirm that database profiles specify a password verify function.

From SQL*Plus:
  select profile, limit from dba_profiles
  where resource_name='PASSWORD_VERIFY_FUNCTION'
  and limit not in ('NULL', 'DEFAULT')
  order by profile;

If no rows are listed, this is a Finding.

Review the code for the password verify function or have the DBA demonstrate a password change to ensure that the function requires new passwords to differ from old passwords by more than 4 characters.

If reviewing code, logic similar to the following should be discovered:

-- Check if the password differs from the previous password
-- by more than 4 characters

if old_password is not null then
 differ:=length(old_password) - length(password);
 
 if abs(differ) <= 4 then
  if length(password) < length(old_password) then
   m:=length(password);
  else
   m:=length(old_password);
  end if;

  differ:=abs(differ);
  for i in 1..m loop
   if substr(password,i,1) != substr(old_password,i,1) then
    differ:=differ + 1;
   end if;
  end loop;

  if differ <= 4 then
    raise_application_error(-20004, 'Password should differ by more than 4 characters');
  end if;
 end if;
end if;

If any password_verify_function routines do not check for a difference of more than 4 characters, this is a Finding."
  desc 'fix', 'Define and apply a password_verify_function for all profiles where passwords are used to authenticate accounts.

See Fix information for DG0079 to create a password_verify_function that meets STIG requirements.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-28977r4_chk'
  tag severity: 'medium'
  tag gid: 'V-3815'
  tag rid: 'SV-24387r3_rule'
  tag stig_id: 'DG0071-ORACLE11'
  tag gtitle: 'DBMS password change variance'
  tag fix_id: 'F-25981r1_fix'
  tag responsibility: 'Database Administrator'
end
