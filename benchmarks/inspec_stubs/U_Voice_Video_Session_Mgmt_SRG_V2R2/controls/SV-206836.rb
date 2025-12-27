control 'SV-206836' do
  title 'In the event of a system failure, Voice Video Session Managers must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving voice video session manager state information helps to facilitate restart and return to the operational mode of the organization with less disruption to mission-essential processes. This control only applies to Committee on National Security Systems Instruction (CNSSI) 1253 high confidentiality and integrity baselines.'
  desc 'check', 'Verify that in the event of a system failure, the Voice Video Session Managers preserves any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

If the Voice Video Session Managers does not preserve all information necessary to determine cause of failure, this is a finding.

If the Voice Video Session Managers does not preserve all information necessary to return to operations with least disruption to mission processes, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager, in the event of a system failure, to preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7091r364697_chk'
  tag severity: 'medium'
  tag gid: 'V-206836'
  tag rid: 'SV-206836r508661_rule'
  tag stig_id: 'SRG-NET-000236-VVSM-00047'
  tag gtitle: 'SRG-NET-000236'
  tag fix_id: 'F-7091r364698_fix'
  tag 'documentable'
  tag legacy: ['V-62117', 'SV-76607']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
