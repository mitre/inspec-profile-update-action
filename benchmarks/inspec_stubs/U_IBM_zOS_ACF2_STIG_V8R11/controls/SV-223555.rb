control 'SV-223555' do
  title 'IBM z/OS system administrator must develop a process to notify ISSOs of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable an existing disabled account. Sending notification of account enabling actions to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
  desc 'check', 'Ask the system Administrator for the documented processes to notify the Information System Security Officers (ISSOs) of account enabling actions.

If there is no process documented, this is a finding.'
  desc 'fix', 'Develop a documented process to notify the Information System Security Officers (ISSOs) of account enabling actions.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25228r500800_chk'
  tag severity: 'medium'
  tag gid: 'V-223555'
  tag rid: 'SV-223555r533198_rule'
  tag stig_id: 'ACF2-OS-000190'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25216r500801_fix'
  tag 'documentable'
  tag legacy: ['SV-106919', 'V-97815']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
