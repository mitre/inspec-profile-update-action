control 'SV-216093' do
  title 'The operating system must enforce password complexity requiring that at least one lowercase character is used.'
  desc 'Complex passwords can reduce the likelihood of success of automated password-guessing attacks.'
  desc 'check', 'Check the MINLOWER setting.

# grep ^MINLOWER /etc/default/passwd

If MINLOWER is not set to 1 or more, this is a finding.'
  desc 'fix', 'The root role is required.
# pfedit /etc/default/passwd 

Locate the line containing:

MINLOWER

Change the line to read:

MINLOWER=1'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17331r372661_chk'
  tag severity: 'medium'
  tag gid: 'V-216093'
  tag rid: 'SV-216093r603268_rule'
  tag stig_id: 'SOL-11.1-040080'
  tag gtitle: 'SRG-OS-000070'
  tag fix_id: 'F-17329r372662_fix'
  tag 'documentable'
  tag legacy: ['SV-60853', 'V-47981']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
