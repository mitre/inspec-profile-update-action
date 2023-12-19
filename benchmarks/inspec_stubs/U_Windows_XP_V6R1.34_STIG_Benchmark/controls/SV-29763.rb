control 'SV-29763' do
  title 'POSIX subsystem registry key exists.'
  desc 'For the system to comply with Security requirements, the POSIX subsystem must be disabled.'
  desc 'fix', 'Remove the following Registry value from the Windows Registry:

HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Subsystems\\Posix'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1083'
  tag rid: 'SV-29763r1_rule'
  tag gtitle: 'POSIX subsystem registry'
  tag fix_id: 'F-67r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
