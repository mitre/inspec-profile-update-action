control 'SV-227590' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Check the MAXREPEATS setting.
# grep MAXREPEATS /etc/default/passwd
If the MAXREPEATS setting is greater than 3, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set MAXREPEATS to 3.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29752r488318_chk'
  tag severity: 'medium'
  tag gid: 'V-227590'
  tag rid: 'SV-227590r603266_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29740r488319_fix'
  tag 'documentable'
  tag legacy: ['V-11975', 'SV-27126']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
