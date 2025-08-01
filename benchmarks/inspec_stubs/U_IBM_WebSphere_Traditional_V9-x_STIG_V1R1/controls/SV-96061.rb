control 'SV-96061' do
  title 'The WebSphere Application Server secure LDAP (LDAPS) must be used for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 

Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted. 

To ensure an error-free operation for this step, first extract to a file the Signer certificate of the LDAP and send that file to the WebSphere Application Server machine. Then add the certificate to the truststore being defined for the LDAP. In this way, you are assured that the remaining actions for this step will be successful.

'
  desc 'check', 'In the administrative console, click Security >> Global security.

Under "User account repository", click "Configure" for the "Standalone LDAP registry", on "Standalone LDAP registry" panel.

If the "SSL" flag is not enabled, this is a finding.'
  desc 'fix', 'In the administrative console, click Security >> Global security.

Under User account repository, click the "Available realm definitions" drop-down list.

Select Standalone LDAP registry.

Click "Configure".

Click "SSL enabled".

Click "OK".

On Global security panel, click "Set as current".

Click "Apply".

Click "Save".

To ensure an error-free operation for this step, you need to first extract to a file the Signer certificate of the LDAP and send that file to the WebSphere Application Server machine. You can then add the certificate to the trust store being defined for the LDAP. In this way, you are assured that the remaining actions for this step will be successful.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81055r2_chk'
  tag severity: 'high'
  tag gid: 'V-81347'
  tag rid: 'SV-96061r1_rule'
  tag stig_id: 'WBSP-AS-001200'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-88133r2_fix'
  tag satisfies: ['SRG-APP-000172-AS-000121', 'SRG-APP-000172-AS-000120']
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
