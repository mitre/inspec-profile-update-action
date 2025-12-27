control 'SV-214220' do
  title 'The Infoblox system must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.

Configuring the DNS server implementation to follow organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Infoblox systems are secure by design and utilize a number of access controls to prevent unauthorized usage. Infoblox systems are purpose built and do not provide privileged "root" level access, nor are they distributed as general purpose operating systems.

By default all services including DNS are disabled on Infoblox systems. Services are enabled only as a result of administrator action.

If any unnecessary services are running on Infoblox systems, this is a finding.'
  desc 'fix', 'Review network architecture and system configuration to ensure a defense in depth architecture which utilizes secure out of band management is utilized.

Review system configuration to ensure all administrators are properly authorized for the functions allowed through system rights.
Validate that both SRG and STIG DNS guidance is properly applied.

Navigate to Grid >> Grid Manager >> Services tab.

Click on each service which is running and review the "Service Status" of each member.
Click on the member and select "Stop" to disable the unnecessary service.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15435r295923_chk'
  tag severity: 'medium'
  tag gid: 'V-214220'
  tag rid: 'SV-214220r612370_rule'
  tag stig_id: 'IDNS-7X-000950'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-15433r295924_fix'
  tag 'documentable'
  tag legacy: ['SV-83121', 'V-68631']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
