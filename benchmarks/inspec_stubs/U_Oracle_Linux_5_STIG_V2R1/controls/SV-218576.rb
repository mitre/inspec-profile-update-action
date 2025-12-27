control 'SV-218576' do
  title 'X Window System connections not required must be disabled.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Determine if the X window system is running.

Procedure:
# ps -ef |grep Xorg

Ask the SA if the X window system is an operational requirement. If it is not, this is a finding.'
  desc 'fix', 'Disable the X Windows server on the system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20051r562804_chk'
  tag severity: 'medium'
  tag gid: 'V-218576'
  tag rid: 'SV-218576r603259_rule'
  tag stig_id: 'GEN005260'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20049r562805_fix'
  tag 'documentable'
  tag legacy: ['V-12018', 'SV-63347']
  tag cci: ['CCI-000381', 'CCI-001436']
  tag nist: ['CM-7 a', 'AC-17 (8)']
end
