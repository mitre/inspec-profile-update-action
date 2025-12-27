control 'SV-233227' do
  title 'The container platform must maintain the confidentiality and integrity of information during reception.'
  desc 'Information either can be unintentionally or maliciously disclosed or modified during reception for reception within the container platform during aggregation, at protocol transformation points, and during container image runtime. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information. When receiving data, the container platform components need to leverage protection mechanisms, such as TLS, TLS VPNs, or IPsec.'
  desc 'check', 'Review documentation and configuration settings to determine if the container platform maintains the confidentiality and integrity of information during reception.

If confidentiality and integrity are not maintained using mechanisms such as TLS, TLS VPNs, or IPsec during reception, this is a finding.'
  desc 'fix', 'Configure the container platform to maintain the confidentiality and integrity using mechanisms such as TLS, TLS VPNs, or IPsec during reception.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36163r599662_chk'
  tag severity: 'medium'
  tag gid: 'V-233227'
  tag rid: 'SV-233227r599663_rule'
  tag stig_id: 'SRG-APP-000442-CTR-001095'
  tag gtitle: 'SRG-APP-000442'
  tag fix_id: 'F-36131r599318_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
