control 'SV-24792' do
  title 'DBMS account passwords should not be set to easily guessed words or values.'
  desc 'DBMS account passwords set to common dictionary words or values render accounts vulnerable to password guessing attacks and unauthorized access.'
  desc 'check', "If no DBMS accounts authenticate using passwords (rare), this check is Not a Finding.  

Confirm that database profiles specify a password verify function.

From SQL*Plus:

  select distinct limit from dba_profiles
  where resource_name= 'PASSWORD_VERIFY_FUNCTION'
  order by limit;

Review the code for the password verify function or have the DBA demonstrate a password change to ensure that the function does not accept passwords that are the same as the username, the name of the database or instance name.

If reviewing code, logic similar to the following should be discovered:

-- Check if the password is too simple. A dictionary of words may be
-- maintained and a check may be made so as not to allow the words
-- that are too simple for the password.

if nls_lower(password) in
('welcome','database','account','user','password','oracle','computer','abcdefgh',
 '12345') then
  raise_application_error(-20002, 'Password too simple');
end if;

If any password_verify_function routines do not check for simple passwords, this is a Finding.

Check also to ensure all password-authenticated accounts specify a password_verify_function.

From SQL*Plus:

  select distinct profile from dba_profiles
  where resource_name='PASSWORD_VERIFY_FUNCTION'
  and (limit is NULL or limit = NULL);

If any profiles are returned that are used by password-authenticated accounts, this is a Finding.

To view the names of password-authenticated accounts:

From SQL*Plus:

  select name from user$ where password is not NULL;"
  desc 'fix', 'Define and apply a Password Verify Function for all profiles where passwords are used to authenticate accounts.

See Fix information for DG0079 to create a Password Verify Function that meets STIG requirements.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29360r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15634'
  tag rid: 'SV-24792r1_rule'
  tag stig_id: 'DG0127-ORACLE11'
  tag gtitle: 'DBMS account password easily guessed'
  tag fix_id: 'F-26386r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
