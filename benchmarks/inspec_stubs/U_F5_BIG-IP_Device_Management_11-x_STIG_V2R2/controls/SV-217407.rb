control 'SV-217407' do
  title 'The BIG-IP appliance must be configured to use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that uses mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that uses mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

If the BIG-IP appliance is not configured to use a properly configured authentication server that uses mechanisms that meet the requirements for authentication to a cryptographic module, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server that uses mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18632r290775_chk'
  tag severity: 'medium'
  tag gid: 'V-217407'
  tag rid: 'SV-217407r879616_rule'
  tag stig_id: 'F5BI-DM-000135'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-18630r513227_fix'
  tag 'documentable'
  tag legacy: ['SV-74685', 'V-60255']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
