control 'SV-38676' do
  title 'All non-interactive/automated processing account passwords must be changed at least once per year or be locked.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password. Locking the password for non-interactive and automated processing accounts is preferred as it removes the possibility of accessing the account by a password. On some systems, locking the passwords of these accounts may prevent the account from functioning properly. Passwords for non-interactive/automated processing accounts must not be used for direct logon to the system.'
  desc 'check', %q(NOTE: This will always require a manual review. This is a local policy issue/question. Ask the SA if there are any automated processing accounts on the system. If there are automated processing accounts on the system, ask the SA if the passwords for those automated accounts are changed at least once a year. If the SA indicates passwords for automated processing accounts are not changed once per year, this is a finding.

Procedure:
Go to last password change date for the system account.
# grep -p <account_name> /etc/security/passwd  | grep lastupdate

To examine the time a password was last changed,  the following perl script has been provided.   Put the lastupdate value in the <lastupdate>.
#perl -e 'use POSIX; print strftime("%c\n" , localtime(<lastupdate>));')
  desc 'fix', 'Implement or establish procedures to change the passwords of automated processing accounts at least once per year.  
#passwd account'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11977'
  tag rid: 'SV-38676r1_rule'
  tag stig_id: 'GEN000740'
  tag gtitle: 'GEN000740'
  tag fix_id: 'F-32066r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
