control 'SV-70255' do
  title 'The web server must employ cryptographic mechanisms (TLS/DTLS/SSL) preventing the unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether the transmission of data between the web server and external devices is encrypted.

If the web server does not encrypt the transmission, this is a finding.'
  desc 'fix', 'Configure the web server to encrypt the transmission of data between the web server and external devices.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56571r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56001'
  tag rid: 'SV-70255r2_rule'
  tag stig_id: 'SRG-APP-000439-WSR-000151'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-60879r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
