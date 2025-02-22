control 'SV-4269' do
  title 'The system must not have unnecessary accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise.  Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for unnecessary user accounts.

Procedure:
# more /etc/passwd

Some examples of unnecessary accounts include games, news, gopher, ftp, and lp.  If any unnecessary accounts are found, this is a finding.'
  desc 'fix', 'Remove all unnecessary accounts, such as games, from the /etc/passwd file before connecting a system to the network. Other accounts, such as news and gopher, associated with a service not in use should also be removed.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2090r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4269'
  tag rid: 'SV-4269r2_rule'
  tag stig_id: 'GEN000290'
  tag gtitle: 'GEN000290'
  tag fix_id: 'F-4180r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
