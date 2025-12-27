control 'SV-44882' do
  title 'Accounts must be locked upon 35 days of inactivity.'
  desc 'On some systems, accounts with disabled passwords still allow access using rcp, remsh, or rlogin through equivalent remote hosts.  All that is required is the remote host name and the user name match an entry in a hosts.equiv file and have a .rhosts file in the user directory.  Using a shell called /bin/false or /dev/null (or an equivalent) will add a layered defense.

Non-interactive accounts on the system, such as application accounts, may be documented exceptions.'
  desc 'check', %q(Indications of inactive accounts are those that have no entries in the last log. Check the date in the last log to verify it is within the last 35 days or the maximum number of days set by the site if more restrictive. If an inactive account is not disabled via an entry in the password field in the /etc/passwd or /etc/shadow (or equivalent), check the /etc/passwd file to check if the account has a valid shell. If an inactive account is found not disabled, this is a finding.

Procedure:
Obtain a list of all active(not locked) accounts:
# for ACCT in $(cut -d: -f1 /etc/passwd)
   do
      if [ "$(passwd -S ${ACCT}| awk '{print $2}')" != "LK" ]
      then
         lastlog -u ${ACCT} |
         awk '{ if(NR>1) printf "%-23s %3s %2s %4s\n", $1, $4, $5, $8}'
      fi
   done

Obtain a list of all accounts that have logged in during the past 35 days:
# lastlog -t 35 | awk '{if(NR>1) printf "%-23s %3s %2s %4s\n", $1, $4, $5, $8}’

Compare the results of the two commands.  Any account listed by the first command that is not also listed by the second command has been inactive for 35 days.)
  desc 'fix', 'All inactive accounts that have not been documented as exceptions will have /bin/false or /sbin/nologin as the default shell in the /etc/passwd file and have the password locked. Examine the user accounts using the lastlog command. Note the date of last login for each account. If any (other than system and application accounts) exceed 35 days or the maximum number of days set by the site, not to exceed 35 days, then lock the account and place a shell field of /bin/false or /sbin/nologin in the passwd file entry for the account.
Procedure:
# passwd -l <inactive_account>
# chsh -s /bin/false <inactive_account>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42336r2_chk'
  tag severity: 'medium'
  tag gid: 'V-918'
  tag rid: 'SV-44882r1_rule'
  tag stig_id: 'GEN000760'
  tag gtitle: 'GEN000760'
  tag fix_id: 'F-38314r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
