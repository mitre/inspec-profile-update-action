control 'SV-227583' do
  title 'The system must require passwords contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'check', 'Check the system password length setting.
# grep PASSLENGTH /etc/default/passwd
If PASSLENGTH is not set to 15 or more, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set the PASSLENGTH variable to 15 or greater.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29745r488297_chk'
  tag severity: 'medium'
  tag gid: 'V-227583'
  tag rid: 'SV-227583r603266_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-29733r488298_fix'
  tag 'documentable'
  tag legacy: ['V-11947', 'SV-27110']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
