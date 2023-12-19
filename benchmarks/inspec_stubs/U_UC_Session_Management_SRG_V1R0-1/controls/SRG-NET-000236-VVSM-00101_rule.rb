control 'SRG-NET-000236-VVSM-00101_rule' do
  title 'In the event of a system failure, Unified Communications Session Managers must be configured to preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving network element state information helps to facilitate network element restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Verify that in the event of a system failure, the Unified Communications Session Managers preserves any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

If the Unified Communications Session Managers does not preserve all information necessary to determine cause of failure, this is a finding.

If the Unified Communications Session Managers does not preserve all information necessary to return to operations with least disruption to mission processes, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager, in the event of a system failure, to preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000236-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000236-VVSM-00101'
  tag rid: 'SRG-NET-000236-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000236-VVSM-00101'
  tag gtitle: 'SRG-NET-000236-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000236-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
