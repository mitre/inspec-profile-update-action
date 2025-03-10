control 'SV-207222' do
  title 'The VPN Gateway must use FIPS 140-2 compliant mechanisms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity and DoD data may be compromised.

VPN gateways utilizing encryption are required to use FIPS compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Verify the VPN Gateway uses FIPS 140-2 compliant mechanisms for authentication to a cryptographic module.

If the VPN Gateway does not use FIPS 140-2 compliant mechanisms for authentication to a cryptographic module, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use FIPS 140-2 compliant mechanisms for authentication to a cryptographic module.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7482r378287_chk'
  tag severity: 'medium'
  tag gid: 'V-207222'
  tag rid: 'SV-207222r608988_rule'
  tag stig_id: 'SRG-NET-000230-VPN-000770'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-7482r378288_fix'
  tag 'documentable'
  tag legacy: ['SV-106261', 'V-97123']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
