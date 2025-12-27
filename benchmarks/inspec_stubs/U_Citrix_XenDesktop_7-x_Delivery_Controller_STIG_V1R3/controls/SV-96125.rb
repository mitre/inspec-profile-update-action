control 'SV-96125' do
  title 'Delivery Controller must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affects the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'To verify that XenDesktop Controller and all other infrastructure server components are installable and manageable by authorized administrative accounts, the following policies must be modified:

Go to Computer Configuration Policies >> Windows Settings >> Security Settings >> Local Policies/User Rights Assignment.

Verify policy settings "Allow log on locally" and "Shut down the system" are both set to the global security group name containing the XenApp or XenDesktop administrators. "Local Administrators" may remain.

If they are not set to the global security group name containing the XenApp or XenDesktop administrators, this is a finding.'
  desc 'fix', 'To ensure that XenDesktop Controller and all other infrastructure server components are installable and manageable by authorized administrative accounts, the following policies must be modified:

Go to Computer Configuration Policies >> Windows Settings >> Security Settings >> Local Policies/User Rights Assignment.

1. Edit "Allow log on locally".

2. Edit "Shut down the system".

3. Change both settings to the global security group name containing the XenApp or XenDesktop administrators. "Local Administrators" may remain.'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x Delivery Controller'
  tag check_id: 'C-81141r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81411'
  tag rid: 'SV-96125r2_rule'
  tag stig_id: 'CXEN-DC-001235'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-88217r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
