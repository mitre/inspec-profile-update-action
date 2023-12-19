control 'SV-69145' do
  title 'The DNS server implementation must maintain the integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Confidentiality is not an objective of DNS, but integrity is. DNS is responsible for maintaining the integrity of DNS information while it is being received.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server maintains the integrity of information during reception. If the DNS server does not maintain integrity during reception, this is a finding.'
  desc 'fix', 'Configure the DNS server to maintain the integrity of information during reception.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55525r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54899'
  tag rid: 'SV-69145r1_rule'
  tag stig_id: 'SRG-APP-000442-DNS-000067'
  tag gtitle: 'SRG-APP-000442-DNS-000067'
  tag fix_id: 'F-59761r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
