control 'SV-227957' do
  title 'The system must use a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration by computer viruses and to limit their spread through intermediate systems.'
  desc 'check', 'The operator will ensure that anti-virus software is installed and operating.

If the operator is unable to provide a documented configuration for an installed anti-virus software system or if not properly used, this is a finding.'
  desc 'fix', 'The operator will ensure that anti-virus software is installed and operating.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30119r490303_chk'
  tag severity: 'medium'
  tag gid: 'V-227957'
  tag rid: 'SV-227957r603266_rule'
  tag stig_id: 'GEN006640'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30107r490304_fix'
  tag 'documentable'
  tag legacy: ['V-12765', 'SV-28461']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
