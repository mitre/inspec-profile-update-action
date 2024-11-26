control 'SV-37314' do
  title 'Accounts must be locked upon 35 days of inactivity.'
  desc 'On some systems, accounts with disabled passwords still allow access using rcp, remsh, or rlogin through equivalent remote hosts.  All that is required is the remote host name and the user name match an entry in a hosts.equiv file and have a .rhosts file in the user directory.  Using a shell called /bin/false or /dev/null (or an equivalent) will add a layered defense.

Non-interactive accounts on the system, such as application accounts, may be documented exceptions.'
  desc 'check', 'Indications of inactive accounts are those that have no entries in the "last" log. Check the date in the "last" log to verify it is within the last 35 days or the maximum numbers of days set by the site if more restrictive. If an inactive account is not disabled via an entry in the password field in the /etc/passwd or /etc/shadow (or equivalent), check the /etc/passwd file to check if the account has a valid shell. 

The passwd command can also be used to list a status for an account.  For example, the following may be used to provide status information on each local account:

NOTE: The following must be done in the BASH shell.

# cut -d: -f1 /etc/passwd | xargs -n1 passwd -S

If an inactive account is found not disabled, this is a finding.'
  desc 'fix', 'All inactive accounts will have /sbin/nologin (or an equivalent), as the default shell in the /etc/passwd file and have the password disabled. Examine the user accounts using the "last" command. Note the date of last login for each account. If any (other than system and application accounts) exceed 35 days or the maximum number of days set by the site, not to exceed 35 days, then disable the accounts using system-config-users tool. Alternately place a shell field of /sbin/nologin /bin/false or /dev/null in the passwd file entry for the account.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36007r4_chk'
  tag severity: 'medium'
  tag gid: 'V-918'
  tag rid: 'SV-37314r2_rule'
  tag stig_id: 'GEN000760'
  tag gtitle: 'GEN000760'
  tag fix_id: 'F-31259r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
