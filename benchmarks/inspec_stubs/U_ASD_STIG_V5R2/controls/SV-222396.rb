control 'SV-222396' do
  title 'The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.'
  desc 'check', 'Review the application documentation and interview the system administrator.

Identify the application encryption capabilities and methods for implementing encryption protection.

For web based applications; open the web browser and access the website URL. Use the browser and determine if the session is protected via TLS. A secure connection is usually indicated in the upper left hand corner of the URL by a padlock icon. Click on the padlock icon and examine the connection information. Determine if TLS encryption is used to secure the session.

For non-web based applications, determine the TCP/IP port, protocol and method used for establishing client connections to the remote server. Review application configuration settings to ensure encryption is specified and  via TLS.

If the connection is not secured with TLS, this is a finding.'
  desc 'fix', 'Design and configure applications to use TLS encryption to protect the confidentiality of remote access sessions.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24066r493096_chk'
  tag severity: 'medium'
  tag gid: 'V-222396'
  tag rid: 'SV-222396r508029_rule'
  tag stig_id: 'APSC-DV-000160'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24055r493097_fix'
  tag 'documentable'
  tag legacy: ['SV-83879', 'V-69257']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
