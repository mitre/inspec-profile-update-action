control 'SV-216090' do
  title 'Users must not reuse the last 5 passwords.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the operating system allows the user to consecutively reuse their password when the password has exceeded its defined lifetime, the end result is a password that is not changed, per policy requirements.'
  desc 'check', 'Determine if the password history setting is configured properly.

# grep ^HISTORY /etc/default/passwd

If HISTORY is commented out or is not set to 5 or more, this is a finding.'
  desc 'fix', 'The root role is required.

# pfedit /etc/default/passwd 

Locate the line containing:

HISTORY

Change the line to read:

HISTORY=5'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17328r372652_chk'
  tag severity: 'medium'
  tag gid: 'V-216090'
  tag rid: 'SV-216090r603268_rule'
  tag stig_id: 'SOL-11.1-040050'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-17326r372653_fix'
  tag 'documentable'
  tag legacy: ['V-47961', 'SV-60833']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
