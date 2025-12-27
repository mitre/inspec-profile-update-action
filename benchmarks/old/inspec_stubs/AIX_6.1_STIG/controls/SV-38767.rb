control 'SV-38767' do
  title 'The system must not have unnecessary accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise.  Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for unnecessary user accounts.

Procedure:
# more /etc/passwd

Some examples of unnecessary accounts includes guest, uucp, games, news, gopher, ftp, and lp. If any unnecessary accounts are found, this is a finding.'
  desc 'fix', 'Remove all unnecessary accounts, such as games, from the /etc/passwd file before connecting a system to the network. Other accounts, such as news and gopher, that are associated with a service not in use should also be removed.

# rmuser -p <username>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36656r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4269'
  tag rid: 'SV-38767r1_rule'
  tag stig_id: 'GEN000290'
  tag gtitle: 'GEN000290'
  tag fix_id: 'F-34155r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
