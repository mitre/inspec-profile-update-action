control 'SV-251702' do
  title 'The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', %q(Check the "/etc/shadow" file for blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.)
  desc 'fix', 'Configure all accounts on the system to have a password or lock the account with the following commands:

Perform a password reset:
$ sudo passwd [username]
Lock an account:
$ sudo passwd -l [username]'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-55139r809218_chk'
  tag severity: 'high'
  tag gid: 'V-251702'
  tag rid: 'SV-251702r809220_rule'
  tag stig_id: 'RHEL-07-010291'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55093r809219_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
