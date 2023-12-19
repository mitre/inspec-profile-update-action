control 'SV-222596' do
  title 'The application must protect the confidentiality and integrity of transmitted information.'
  desc "Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

This requirement applies  to those applications that transmit data, or allow access to data non-locally. Application and data owners have a responsibility for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

Application and data owners need to identify the data that requires cryptographic protection. If no data protection requirements are defined as to what specific data must be encrypted and what data is non-sensitive and doesn't require encryption, all data must be encrypted.
 
When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPSEC.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa."
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify application clients, servers and associated network connections including application networking ports.  

Identify the types of data processed by the application and review any documented data protection requirements.

Identify the application communication protocols.

Review application documents for instructions or guidance on configuring application encryption settings.

Verify the application is configured to enable encryption protections for data in accordance with the data protection requirements. If no data protection requirements exist, ensure all application data is encrypted.

If the application does not utilize TLS, IPsec or other approved encryption mechanism to protect the confidentiality and integrity of transmitted information, this is a finding.'
  desc 'fix', 'Configure all of the application systems to require TLS encryption in accordance with data protection requirements.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24266r493696_chk'
  tag severity: 'high'
  tag gid: 'V-222596'
  tag rid: 'SV-222596r879810_rule'
  tag stig_id: 'APSC-DV-002440'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-24255r493697_fix'
  tag 'documentable'
  tag legacy: ['SV-84867', 'V-70245']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
