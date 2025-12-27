control 'SV-69143' do
  title 'The DNS server implementation must maintain the integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Confidentiality is not an objective of DNS, but integrity is. DNS is responsible for maintaining the integrity of DNS information while it is being prepared for transmission.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server maintains the integrity of information during preparation for transmission. If the DNS server does not maintain the integrity during preparation for transmission, this is a finding.'
  desc 'fix', 'Configure the DNS server to maintain the integrity of information during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54897'
  tag rid: 'SV-69143r1_rule'
  tag stig_id: 'SRG-APP-000441-DNS-000066'
  tag gtitle: 'SRG-APP-000441-DNS-000066'
  tag fix_id: 'F-59759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
