control 'SV-218204' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19679r568546_chk'
  tag severity: 'medium'
  tag gid: 'V-218204'
  tag rid: 'SV-218204r603259_rule'
  tag stig_id: 'GEN000290-2'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19677r568547_fix'
  tag 'documentable'
  tag legacy: ['V-27275', 'SV-63215']
  tag cci: ['CCI-000012', 'CCI-000366']
  tag nist: ['AC-2 j', 'CM-6 b']
end
