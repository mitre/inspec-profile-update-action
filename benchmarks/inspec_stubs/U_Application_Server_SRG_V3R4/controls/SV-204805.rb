control 'SV-204805' do
  title 'The application server, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information.

Application servers must provide the capability to utilize and meet requirements of the DoD Enterprise PKI infrastructure for application authentication, but without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates) when access through the network to the CA is not available.'
  desc 'check', 'Review application server documentation to ensure the application server provides a PKI integration capability that implements a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4925r283056_chk'
  tag severity: 'medium'
  tag gid: 'V-204805'
  tag rid: 'SV-204805r879774_rule'
  tag stig_id: 'SRG-APP-000401-AS-000243'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-4925r283057_fix'
  tag 'documentable'
  tag legacy: ['V-57511', 'SV-71787']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
