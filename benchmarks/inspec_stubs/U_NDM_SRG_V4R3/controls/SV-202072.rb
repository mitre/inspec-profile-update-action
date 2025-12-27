control 'SV-202072' do
  title 'The network device must use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'Determine if the network device uses FIPS 140-2 approved algorithms for authentication to a cryptographic module. 

If the network device is not configured to use a FIPS-approved authentication algorithm to a cryptographic module, this is a finding.'
  desc 'fix', 'Configure the network device to use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2198r381836_chk'
  tag severity: 'high'
  tag gid: 'V-202072'
  tag rid: 'SV-202072r879616_rule'
  tag stig_id: 'SRG-APP-000179-NDM-000265'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-2199r381837_fix'
  tag 'documentable'
  tag legacy: ['SV-69399', 'V-55153']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
