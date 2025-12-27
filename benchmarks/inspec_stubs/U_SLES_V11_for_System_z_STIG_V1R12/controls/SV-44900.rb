control 'SV-44900' do
  title 'The root account must be the only account having a UID of 0.'
  desc 'If an account has a UID of 0, it has root authority.  Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', %q(Check the system for duplicate UID 0 assignments by listing all accounts assigned UID 0.

Procedure:
# cat /etc/passwd | awk -F":" '{print$1":"$3":"}' | grep ":0:"

If any accounts other than root are assigned UID 0, this is a finding.)
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42340r1_chk'
  tag severity: 'medium'
  tag gid: 'V-773'
  tag rid: 'SV-44900r1_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'GEN000880'
  tag fix_id: 'F-38332r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
