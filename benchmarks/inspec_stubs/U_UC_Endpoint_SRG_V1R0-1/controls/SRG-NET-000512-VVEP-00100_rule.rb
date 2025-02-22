control 'SRG-NET-000512-VVEP-00100_rule' do
  title 'The Unified Communications Endpoint must be configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network element to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.'
  desc 'check', 'Verify that the Unified Communications Endpoint is configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If the Unified Communications Endpoint is not configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000512-VVEP-00100_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000512-VVEP-00100'
  tag rid: 'SRG-NET-000512-VVEP-00100_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00100'
  tag gtitle: 'SRG-NET-000512-VVEP-00100'
  tag fix_id: 'F-SRG-NET-000512-VVEP-00100_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
