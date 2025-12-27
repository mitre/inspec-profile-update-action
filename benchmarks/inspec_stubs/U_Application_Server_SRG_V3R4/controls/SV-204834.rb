control 'SV-204834' do
  title 'The application server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If the application server is not configured in accordance with security configuration settings, this is a finding.'
  desc 'fix', 'Configure the application server to be in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4954r283143_chk'
  tag severity: 'medium'
  tag gid: 'V-204834'
  tag rid: 'SV-204834r879887_rule'
  tag stig_id: 'SRG-APP-000516-AS-000237'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-4954r283144_fix'
  tag 'documentable'
  tag legacy: ['SV-71775', 'V-57499']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
