control 'SV-205253' do
  title 'The DNS server implementation must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.

Configuring the DNS server implementation to follow organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs. If the DNS server is not configured in accordance with these settings, this is a finding.'
  desc 'fix', 'Configure the DNS server to be in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5520r392672_chk'
  tag severity: 'medium'
  tag gid: 'V-205253'
  tag rid: 'SV-205253r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000500'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5520r392673_fix'
  tag 'documentable'
  tag legacy: ['SV-69475', 'V-55229']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
