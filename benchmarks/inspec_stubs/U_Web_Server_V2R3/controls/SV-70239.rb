control 'SV-70239' do
  title 'The web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the web server to implement organization-wide security implementation guides and security checklists guarantees compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the web server, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if web server is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance.

If the web server is not configured according to the guidance, this is a finding.'
  desc 'fix', 'Configure the web server to be configured according to DoD security configuration guidance.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56555r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55985'
  tag rid: 'SV-70239r2_rule'
  tag stig_id: 'SRG-APP-000516-WSR-000174'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-60863r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
