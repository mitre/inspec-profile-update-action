control 'SV-95485' do
  title 'The SDN controllers must be configured as a cluster in active/active or active/passive mode to preserve any information necessary to determine cause of a system failure and to maintain network operations with least disruption to workload processes and flows.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the SDN controller. Preserving network element state information helps to facilitate continuous network operations minimal or no disruption to mission-essential workload processes and flows.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to peer with one or more controllers in an active/active or active/passive failover mode.  

If the SDN controller is not configured to be deployed as a cluster in active/active or active/passive mode, this is a finding.'
  desc 'fix', 'Configure the SDN controller to peer with one or more controllers in an active/active or active/passive failover mode.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80775'
  tag rid: 'SV-95485r1_rule'
  tag stig_id: 'SRG-NET-000236-SDN-000365'
  tag gtitle: 'SRG-NET-000236'
  tag fix_id: 'F-87629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
