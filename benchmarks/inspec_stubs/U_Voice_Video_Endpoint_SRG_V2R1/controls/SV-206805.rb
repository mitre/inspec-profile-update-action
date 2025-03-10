control 'SV-206805' do
  title 'The Voice Video Endpoint must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the Voice Video Endpoint to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.'
  desc 'check', 'Verify the Voice Video Endpoint is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs. This requirement is intended to be used to allow best practices and other security guidance to be included within a vendor-produced STIG.

If the Voice Video Endpoint is not configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7061r363938_chk'
  tag severity: 'medium'
  tag gid: 'V-206805'
  tag rid: 'SV-206805r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00060'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7061r363939_fix'
  tag 'documentable'
  tag legacy: ['SV-81291', 'V-66801']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
