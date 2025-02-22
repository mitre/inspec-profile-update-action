control 'SV-226442' do
  title 'The system must not have unnecessary accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise.  Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for unnecessary user accounts.

Procedure:
# more /etc/passwd

Some examples of unnecessary accounts include games, news, gopher, ftp, and lp. 

If an unnecessary account is found and its use is not justified and documented with the ISSO, this is a finding.'
  desc 'fix', 'Remove all unnecessary accounts, such as games, from the /etc/passwd file before connecting a system to the network. Other accounts, such as news and gopher, associated with a service not in use should also be removed.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36373r602722_chk'
  tag severity: 'medium'
  tag gid: 'V-226442'
  tag rid: 'SV-226442r603265_rule'
  tag stig_id: 'GEN000290'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36337r602723_fix'
  tag 'documentable'
  tag legacy: ['SV-4269', 'V-4269']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
