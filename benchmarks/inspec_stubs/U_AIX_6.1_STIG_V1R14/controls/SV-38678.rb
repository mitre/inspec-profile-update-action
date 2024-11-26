control 'SV-38678' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder. Many computer compromises occur as the result of account name and password guessing. This is generally done by someone with an automated script using repeated logon attempts until the correct account and password pair is guessed. Utilities, such as cracklib, can be used to validate that passwords are not dictionary words and meet other criteria during password changes.'
  desc 'check', 'Procedure:
#lsuser -a dictionlist ALL

If the dictionlist is blank or not listed, the system is not checking against a dictionary of words that are not to be used for passwords.  This is a finding.'
  desc 'fix', "Install the default dictionary of words from the 'bos.data' fileset with smitty or installp.
# smitty installp
#installp bos.data 

Customize or modify the dictionary in /usr/share/dict/words as necessary.
#vi /usr/share/dict/words

Add a dictionary list to /etc/security/user file with the chsec command.
#chsec -f /etc/security/user -s default -a dictionlist=/usr/share/dict/words"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36908r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22307'
  tag rid: 'SV-38678r1_rule'
  tag stig_id: 'GEN000790'
  tag gtitle: 'GEN000790'
  tag fix_id: 'F-32089r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000189']
  tag nist: ['IA-5 (4)']
end
