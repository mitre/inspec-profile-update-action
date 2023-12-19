control 'SV-220024' do
  title 'Accounts must be locked upon 35 days of inactivity.'
  desc 'On some systems, accounts with disabled passwords still allow access using rcp, remsh, or rlogin through equivalent remote hosts. All that is required is the remote host name and the user name match an entry in a hosts.equiv file and have a .rhosts file in the user directory. Using a shell called /bin/false or /dev/null (or an equivalent) will add a layered defense.

Non-interactive accounts on the system, such as application accounts, may be documented exceptions.'
  desc 'check', %q(Indications of inactive accounts are those without entries in the last log. Check the date in the last log to verify it is within the last 35 days.

Obtain a listing of user accounts.
#cat /etc/passwd | cut -f1 -d ":"

Run the last command for each user account.
# last < user account >

If any user's account has not been accessed in the last 35 days and the account is not disabled via an entry in the password field in the /etc/passwd or /etc/shadow (or equivalent), check the /etc/passwd file to check if the account has a valid shell. If an inactive account is found that is not disabled, this is a finding.)
  desc 'fix', 'All inactive accounts will have /bin/false, /usr/bin/false, or /dev/null as the default shell in the /etc/passwd file and have the password disabled. Disable the inactive accounts. Examine the inactive accounts using the last command. Note the date of last login for each account. If any (other than system and application accounts) exceed 35 days, then disable them by placing a shell of /bin/false or /dev/null in the shell field of the passwd file entry for that account. An alternative, and preferable method, is to disable the account using smc or the passwd command.

# passwd -l < account to lock >'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36362r602689_chk'
  tag severity: 'medium'
  tag gid: 'V-220024'
  tag rid: 'SV-220024r603265_rule'
  tag stig_id: 'GEN000760'
  tag gtitle: 'SRG-OS-000003'
  tag fix_id: 'F-36326r602690_fix'
  tag 'documentable'
  tag legacy: ['SV-39824', 'V-918']
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
