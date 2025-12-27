control 'SV-251422' do
  title 'The Ivanti MobileIron Core server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Review the MDM server documentation, Mobile Device Management Protection Profile Guide.

If Core is not configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs, this is a finding.'
  desc 'fix', 'Configure the MDM Server per the Mobile Device Management Protection Profile and this document.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54857r806396_chk'
  tag severity: 'medium'
  tag gid: 'V-251422'
  tag rid: 'SV-251422r806398_rule'
  tag stig_id: 'IMIC-11-012600'
  tag gtitle: 'SRG-APP-000516-UEM-000391'
  tag fix_id: 'F-54810r806397_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
