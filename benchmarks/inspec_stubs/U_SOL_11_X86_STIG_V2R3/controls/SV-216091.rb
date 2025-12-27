control 'SV-216091' do
  title 'The system must require at least eight characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure old and new passwords have significant differences. Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', 'Check /etc/default/passwd to verify the MINDIFF setting.

# grep ^MINDIFF /etc/default/passwd

If the setting is not present, or is less than 8, this is a finding.'
  desc 'fix', 'The root role is required.

# pfedit /etc/default/passwd 

Search for MINDIFF. Change the line to read:

MINDIFF=8'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17329r372655_chk'
  tag severity: 'medium'
  tag gid: 'V-216091'
  tag rid: 'SV-216091r603268_rule'
  tag stig_id: 'SOL-11.1-040060'
  tag gtitle: 'SRG-OS-000072'
  tag fix_id: 'F-17327r372656_fix'
  tag 'documentable'
  tag legacy: ['SV-60839', 'V-47967']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
