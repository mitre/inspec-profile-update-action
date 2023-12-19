control 'SV-233881' do
  title 'The Infoblox system must use the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.

Configuring the DNS server implementation to follow organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Infoblox systems are secure by design and use a number of access controls to prevent unauthorized usage. Infoblox systems are purpose built and do not provide privileged "root" level access, nor are they distributed as general purpose operating systems. By default all services including DNS are disabled on Infoblox systems. Services are enabled only as a result of administrator action. 

1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration.  
2. Select the "Services" tab.  
3. Review the enabled services.  

If any unnecessary services are running on Infoblox systems, this is a finding.'
  desc 'fix', 'Review network architecture and system configuration to ensure use of a defense-in-depth architecture that uses secure out-of-band management.  Review system configuration to ensure that all administrators are properly authorized for the functions allowed through system rights. 

1. Validate that both SRG and STIG DNS guidance is properly applied. 
2. Navigate to Grid >> Grid Manager >> Services tab.  
3. Click on each service that is running and review the "Service Status" of each member.  
4. Click on the member and select "Stop" to disable the unnecessary service.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37066r611163_chk'
  tag severity: 'medium'
  tag gid: 'V-233881'
  tag rid: 'SV-233881r621666_rule'
  tag stig_id: 'IDNS-8X-400023'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37031r611164_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
