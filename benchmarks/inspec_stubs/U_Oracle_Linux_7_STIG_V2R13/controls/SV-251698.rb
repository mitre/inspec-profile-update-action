control 'SV-251698' do
  title 'The Oracle Linux operating system must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', %q(Check the "/etc/shadow" file for blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.)
  desc 'fix', 'Configure all accounts on the system to have a password or lock the account with the following commands:

Perform a password reset:
$ sudo passwd [username]
Lock an account:
$ sudo passwd -l [username]'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-55135r809172_chk'
  tag severity: 'high'
  tag gid: 'V-251698'
  tag rid: 'SV-251698r809174_rule'
  tag stig_id: 'OL07-00-010291'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55089r809173_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
