control 'SV-216079' do
  title 'X Window System connections that are not required must be disabled.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Determine if the X Window system is running.

Procedure:
# ps -ef |grep X

Ask the SA if the X Window system is an operational requirement. If it is not, this is a finding.'
  desc 'fix', 'Disable the X Windows server on the system.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17317r372619_chk'
  tag severity: 'medium'
  tag gid: 'V-216079'
  tag rid: 'SV-216079r603268_rule'
  tag stig_id: 'SOL-11.1-020560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17315r372620_fix'
  tag 'documentable'
  tag legacy: ['V-61031', 'SV-75499']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
