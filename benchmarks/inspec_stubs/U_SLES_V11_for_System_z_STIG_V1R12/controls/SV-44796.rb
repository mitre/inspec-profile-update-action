control 'SV-44796' do
  title 'The system must not have the unnecessary news account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "news" accounts.

Procedure:
# rpm -q inn
If the "inn" is installed the "news" user is necessary and this is not a finding.

# grep ^news /etc/passwd
If this account exists and "inn" is not installed, this is a finding.'
  desc 'fix', 'Remove the "news" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42290r1_chk'
  tag severity: 'medium'
  tag gid: 'V-27275'
  tag rid: 'SV-44796r1_rule'
  tag stig_id: 'GEN000290-2'
  tag gtitle: 'GEN000290-2'
  tag fix_id: 'F-38246r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
