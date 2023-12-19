control 'SV-221521' do
  title 'OHS must have the SSLFIPS directive enabled to prevent unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23236r415242_chk'
  tag severity: 'high'
  tag gid: 'V-221521'
  tag rid: 'SV-221521r879810_rule'
  tag stig_id: 'OH12-1X-000309'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-23225r415243_fix'
  tag 'documentable'
  tag legacy: ['SV-79033', 'V-64543']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
