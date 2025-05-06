control 'SV-234251' do
  title 'The Citrix Storefront server must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.'
  desc 'check', 'A DoD approved VPN, or gateway/proxy, must be leveraged to access StoreFront from a remote network. This VPN, or gateway, must handle user authentication and tunneling of StoreFront traffic. The VPN, or gateway, must meet the DoD encryption requirements, such as FIPS 140-2, for the environment.

If no VPN, or gateway/proxy, is used for remote access to StoreFront, this is a finding.
If the VPN, or gateway/proxy, does not authenticate the remote user before providing access to StoreFront, this is a finding.
If the VPN, or gateway/proxy, fails to meet the DoD encryption requirements for the environment, this is a finding.'
  desc 'fix', 'Implement a DoD approved VPN, or gateway/proxy, that will authenticate user access and tunnel/proxy traffic to StoreFront. Ensure the VPN, or gateway/proxy, is configured to authenticate the user before accessing the environment, and meets the DoD encryption requirements, such as FIPS 140-2, for the environment.'
  impact 0.7
  ref 'DPMS Target Citrix VAD 7.x StoreFront'
  tag check_id: 'C-37436r612113_chk'
  tag severity: 'high'
  tag gid: 'V-234251'
  tag rid: 'SV-234251r628797_rule'
  tag stig_id: 'CVAD-SF-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37401r612114_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
