control 'SV-773' do
  title 'The root account must be the only account having an UID of 0.'
  desc 'If an account has an UID of 0, it has root authority. Multiple accounts with an UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', %q(Check the system for duplicate UID 0 assignments by listing all accounts assigned UID 0.

Procedure:
# grep ":0:" /etc/passwd | awk -F":" '{print$1":"$3":"}' | grep ":0:"

If any accounts other than root are assigned UID 0, this is a finding.)
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28053r1_chk'
  tag severity: 'medium'
  tag gid: 'V-773'
  tag rid: 'SV-773r2_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'GEN000880'
  tag fix_id: 'F-24403r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
