control 'SV-12519' do
  title 'X Window System connections that are not required must be disabled.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Determine if the X Window system is running.

Procedure:
# ps -ef |grep X

Ask the SA if the X Window system is an operational requirement. If it is not, this is a finding.'
  desc 'fix', 'Disable the X Windows server on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7981r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12018'
  tag rid: 'SV-12519r2_rule'
  tag stig_id: 'GEN005260'
  tag gtitle: 'GEN005260'
  tag fix_id: 'F-11277r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
