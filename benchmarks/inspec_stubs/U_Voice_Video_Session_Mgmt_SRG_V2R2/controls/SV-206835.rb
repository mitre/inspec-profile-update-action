control 'SV-206835' do
  title 'The Voice Video Session Manager must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving voice video session manager state information helps to facilitate restart and return to the operational mode of the organization with less disruption to mission-essential processes.

This applies to the configuration of the functionality of the voice video session manager. Abort refers to stopping a program or function before it has finished naturally and refers to both requested and unexpected terminations. This control only applies to Committee on National Security Systems Instruction (CNSSI) 1253 high confidentiality and integrity baselines.'
  desc 'check', 'Verify the Voice Video Session Manager fails to a secure state when system initialization fails, shutdown fails, or aborts fail.

If the Voice Video Session Manager does not fail to a secure state if system initialization fails, shutdown fails, or aborts fail, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7090r364694_chk'
  tag severity: 'medium'
  tag gid: 'V-206835'
  tag rid: 'SV-206835r508661_rule'
  tag stig_id: 'SRG-NET-000235-VVSM-00046'
  tag gtitle: 'SRG-NET-000235'
  tag fix_id: 'F-7090r364695_fix'
  tag 'documentable'
  tag legacy: ['SV-76595', 'V-62105']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
