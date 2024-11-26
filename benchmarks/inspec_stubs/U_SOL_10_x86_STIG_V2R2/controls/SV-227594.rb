control 'SV-227594' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder.  Many computer compromises occur as the result of account name and password guessing.  This is generally done by someone with an automated script using repeated logon attempts until the correct account and password pair is guessed.  Utilities, such as cracklib, can be used to validate passwords are not dictionary words and meet other criteria during password changes.'
  desc 'check', 'Check /etc/default/passwd for dictionary check configuration.

# grep DICTION /etc/default/passwd

If the DICTIONLIST or DICTIONDBDIR settings are not present, or are set to non-existent files or directories, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd; add or set DICTIONLIST to the dictionary file and DICTIONDBDIR to a database directory such as /var/passwd.  Generate the password dictionary by running the mkpwdict command.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29756r488333_chk'
  tag severity: 'medium'
  tag gid: 'V-227594'
  tag rid: 'SV-227594r603266_rule'
  tag stig_id: 'GEN000790'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29744r488334_fix'
  tag 'documentable'
  tag legacy: ['V-22307', 'SV-26345']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
