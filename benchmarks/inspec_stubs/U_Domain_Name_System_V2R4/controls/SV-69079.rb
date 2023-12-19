control 'SV-69079' do
  title 'In the event of a system failure, the DNS server implementation must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server preserves any information necessary to determine cause of system failure and any information necessary to return to operations with least disruption to mission processes. If the DNS server does not preserve the necessary information, this is a finding.'
  desc 'fix', 'Configure the DNS server to preserve any information necessary to determine cause of system failure and any information necessary to return to operations with least disruption to mission processes.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55455r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54833'
  tag rid: 'SV-69079r1_rule'
  tag stig_id: 'SRG-APP-000226-DNS-000032'
  tag gtitle: 'SRG-APP-000226-DNS-000032'
  tag fix_id: 'F-59691r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
