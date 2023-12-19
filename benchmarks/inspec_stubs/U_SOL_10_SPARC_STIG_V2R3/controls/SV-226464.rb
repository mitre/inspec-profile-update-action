control 'SV-226464' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Check the MAXREPEATS setting.
# grep MAXREPEATS /etc/default/passwd
If the MAXREPEATS setting is greater than 3, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set MAXREPEATS to 3.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28625r482768_chk'
  tag severity: 'medium'
  tag gid: 'V-226464'
  tag rid: 'SV-226464r603265_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28613r482769_fix'
  tag 'documentable'
  tag legacy: ['SV-27126', 'V-11975']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
