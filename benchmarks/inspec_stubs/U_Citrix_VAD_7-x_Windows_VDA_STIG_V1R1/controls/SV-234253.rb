control 'SV-234253' do
  title 'Citrix Windows Virtual Delivery Agent must implement DoD-approved encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'A DoD approved VPN, or gateway/proxy, must be leveraged to access the Windows VDA from a remote network. This VPN, or gateway, must handle user authentication and tunneling of Citrix traffic. The VPN, or gateway, must meet the DoD encryption requirements, such as FIPS 140-2, for the environment.

If no VPN, or gateway/proxy, is used for remote access to the VDA, this is a finding.
If the VPN, or gateway/proxy, does not authenticate the remote user before providing access to the VDA, this is a finding.
If the VPN, or gateway/proxy, fails to meet the DoD encryption requirements for the environment, this is a finding.'
  desc 'fix', 'Implement a DoD-approved VPN or gateway/proxy that will authenticate user access and tunnel/proxy traffic to the Windows VDA. Ensure the VPN or gateway/proxy is configured to authenticate the user before accessing the environment, and meets the DoD encryption requirements, such as FIPS 140-2, for the environment.'
  impact 0.7
  ref 'DPMS Target Citrix VAD 7.x Windows VDA'
  tag check_id: 'C-37438r612302_chk'
  tag severity: 'high'
  tag gid: 'V-234253'
  tag rid: 'SV-234253r628798_rule'
  tag stig_id: 'CVAD-VD-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37403r612303_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000015', 'SRG-APP-000039', 'SRG-APP-000219', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001184', 'CCI-001414', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'SC-23', 'AC-4', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
