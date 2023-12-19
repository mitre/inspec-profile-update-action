control 'SV-38840' do
  title 'Accounts must be locked upon 35 days of inactivity.'
  desc 'On some systems, accounts with disabled passwords still allow access using rcp, remsh, or rlogin through equivalent remote hosts. All that is required is the remote host name and the user name match an entry in a hosts.equiv file and have a .rhosts file in the user directory. Using a shell called /bin/false or /dev/null (or an equivalent) will add a layered defense.

Non-interactive accounts on the system, such as application accounts, may be documented exceptions.'
  desc 'check', 'Indications of inactive accounts are those without entries in the last log. Check the date in the last log to verify it is within the last 35 days. If an inactive account is not disabled via an invalid login shell /bin/false entry in the shell field of the /etc/passwd file or account_locked = true in /etc/security/user file,  this is a finding.'
  desc 'fix', 'All inactive accounts will have /bin/false, /usr/bin/false, or /dev/null as the default shell in the /etc/passwd file and have the password disabled. Disable the inactive accounts. Examine the inactive accounts using the last command. Note the date of last login for each account. If any (other than system and application accounts) exceed 35 days, then disable them by placing a shell of /bin/false or /dev/null in the shell field of the passwd file entry for that account. An alternative, and preferable method, is to disable the account using SMIT or the chsec command. 

Change the accounts login shell.
#chsh <account> /bin/false

Lock the account in /etc/security/user file.
 #chuser account_locked=true < user id >
OR
# smitty chuser'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-918'
  tag rid: 'SV-38840r1_rule'
  tag stig_id: 'GEN000760'
  tag gtitle: 'GEN000760'
  tag fix_id: 'F-33093r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
