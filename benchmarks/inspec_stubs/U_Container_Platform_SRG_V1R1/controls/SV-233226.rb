control 'SV-233226' do
  title 'The container platform must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information may be unintentionally or maliciously disclosed or modified during preparation for transmission within the container platform during aggregation, at protocol transformation points, and during container image runtime. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information. When transmitting data, the container platform components need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPsec.'
  desc 'check', 'Review the documentation and deployed configuration to determine if the container platform maintains the confidentiality and integrity of information during preparation before transmission. 

If the confidentiality and integrity are not maintained using mechanisms such as TLS, TLS VPNs, or IPsec during preparation before transmission, this is a finding.'
  desc 'fix', 'Configure the container platform to maintain the confidentiality and integrity of information using mechanisms such as TLS, TLS VPNs, or IPsec during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36162r599660_chk'
  tag severity: 'medium'
  tag gid: 'V-233226'
  tag rid: 'SV-233226r599661_rule'
  tag stig_id: 'SRG-APP-000441-CTR-001090'
  tag gtitle: 'SRG-APP-000441'
  tag fix_id: 'F-36130r599315_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
