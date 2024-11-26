control 'SV-205186' do
  title 'In the event of a system failure, the DNS server implementation must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server preserves any information necessary to determine cause of system failure and any information necessary to return to operations with least disruption to mission processes. If the DNS server does not preserve the necessary information, this is a finding.'
  desc 'fix', 'Configure the DNS server to preserve any information necessary to determine cause of system failure and any information necessary to return to operations with least disruption to mission processes.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5453r392471_chk'
  tag severity: 'medium'
  tag gid: 'V-205186'
  tag rid: 'SV-205186r879641_rule'
  tag stig_id: 'SRG-APP-000226-DNS-000032'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-5453r392472_fix'
  tag 'documentable'
  tag legacy: ['SV-69079', 'V-54833']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
