control 'SV-207261' do
  title 'The VPN Gateway must use an approved High Assurance Commercial Solution for Classified (CSfC) cryptographic algorithm for remote access to a classified network.'
  desc "Use of improperly configured or lower assurance equipment and solutions could compromise high-value information.

The National Security Agency/Central Security Service's (NSA/CSS) CSfC Program enables commercial products to be used in layered solutions to protect classified National Security Systems (NSS) data. Currently, Suite B cryptographic algorithms are specified by the National Institute of Standards and Technology (NIST) and are used by NSA's Information Assurance Directorate in solutions approved for protecting classified and unclassified NSS. However, quantum resistant algorithms will be required for future Suite B implementations."
  desc 'check', 'Verify the VPN Gateway uses an approved High Assurance Commercial Solution for Classified (CSfC) cryptographic algorithm for remote access to a classified network.

If the VPN Gateway does not use an approved High Assurance Commercial Solution for Classified (CSfC) cryptographic algorithm for remote access to a classified network, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use an approved High Assurance Commercial Solution for Classified (CSfC) cryptographic algorithm for remote access to a classified network.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7521r378404_chk'
  tag severity: 'high'
  tag gid: 'V-207261'
  tag rid: 'SV-207261r608988_rule'
  tag stig_id: 'SRG-NET-000565-VPN-002390'
  tag gtitle: 'SRG-NET-000565'
  tag fix_id: 'F-7521r378405_fix'
  tag 'documentable'
  tag legacy: ['SV-106355', 'V-97217']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
