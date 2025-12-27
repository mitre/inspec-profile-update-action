control 'SV-250347' do
  title 'The WebSphere Liberty Server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'Export grade encryption suites are not strong and do not meet DoD requirements. The encryption for the session becomes easy for the attacker to break. Do not use export grade encryption.'
  desc 'check', 'Review the ${server.config.dir}/server.xml file and check the "enabledCiphers" setting. If any of the ciphers specified in the enabledCiphers setting contains the word "EXPORT", this is a finding. 

<ssl id="myDefaultSSLConfig"
       keyStoreRef="defaultKeyStore"
       trustStoreRef="defaultTrustStore"
       clientAuthentication="true"
       sslProtocol="TLS" 
       enabledCiphers="SSL_xxx_yyy_zzz"/>'
  desc 'fix', 'Review the ${server.config.dir}/server.xml file and if needed, modify the "enabledCiphers" setting for each affected SSL configuration.

<ssl id="myDefaultSSLConfig"
       keyStoreRef="defaultKeyStore"
       trustStoreRef="defaultTrustStore"
       clientAuthentication="true"
       sslProtocol="TLS" 
       enabledCiphers="SSL_xxx_yyy_zzz"/> 

where xxx, yyy, and zzz do not contain "EXPORT".'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53782r795092_chk'
  tag severity: 'medium'
  tag gid: 'V-250347'
  tag rid: 'SV-250347r795094_rule'
  tag stig_id: 'IBMW-LS-001110'
  tag gtitle: 'SRG-APP-000439-AS-000274'
  tag fix_id: 'F-53736r795093_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
