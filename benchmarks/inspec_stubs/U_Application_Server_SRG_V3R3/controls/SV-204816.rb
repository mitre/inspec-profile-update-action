control 'SV-204816' do
  title 'The application server must protect the confidentiality and integrity of transmitted information through the use of an approved TLS version.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the application server and a large number of devices/applications external to the application server.  Examples are a web client used by a user, a backend database, a log server, or other application servers in an application server cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure.  The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.

TLS must be enabled and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Review the application server documentation and deployed configuration to determine which version of TLS is being used.

If the application server is not using TLS to maintain the confidentiality and integrity of transmitted information or non-FIPS-approved SSL versions are enabled, this is a finding.'
  desc 'fix', 'Configure the application server to use a FIPS-2 approved TLS version to maintain the confidentiality and integrity of transmitted information and to disable all non-FIPS-approved SSL versions.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4936r283089_chk'
  tag severity: 'medium'
  tag gid: 'V-204816'
  tag rid: 'SV-204816r850868_rule'
  tag stig_id: 'SRG-APP-000439-AS-000155'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-4936r283090_fix'
  tag 'documentable'
  tag legacy: ['V-57533', 'SV-71809']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
