control 'SV-82811' do
  title 'The Mainframe Product must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Refer to site security configuration policies.

Refer to Mainframe Product security documentation.

Examine configuration settings.

If configuration settings do not adhere to site policies, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to adhere to site policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68321'
  tag rid: 'SV-82811r1_rule'
  tag stig_id: 'SRG-APP-000516-MFP-000195'
  tag gtitle: 'SRG-APP-000516-MFP-000195'
  tag fix_id: 'F-74435r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
