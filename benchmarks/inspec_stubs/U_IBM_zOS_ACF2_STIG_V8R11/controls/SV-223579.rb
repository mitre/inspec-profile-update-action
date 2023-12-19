control 'SV-223579' do
  title 'IBM z/OS system administrator must develop a procedure to notify system administrators and ISSOs of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable an existing disabled account. Sending notification of account enabling actions to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
  desc 'check', 'Ask the system administrator for the procedure to notify system administrators and ISSOs of account enabling actions.

If no procedures are in place, this is a finding.'
  desc 'fix', 'Develop and document a procedure to notify system administrators and ISSOs of account enabling actions.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25252r500872_chk'
  tag severity: 'medium'
  tag gid: 'V-223579'
  tag rid: 'SV-223579r853554_rule'
  tag stig_id: 'ACF2-OS-002390'
  tag gtitle: 'SRG-OS-000304-GPOS-00121'
  tag fix_id: 'F-25240r500873_fix'
  tag 'documentable'
  tag legacy: ['V-97863', 'SV-106967']
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
