control 'SV-237438' do
  title 'The SCOM Web Console must be configured for HTTPS.'
  desc 'HTTP sessions are sent in clear text and can allow a man in the middle to recon the environment. The web console itself does not allow for administrative actions, so most of the risk associated with http authentication is inherently mitigated. However, this would allow an attacker to intercept SCOM web-console traffic for reconnaissance purposes.'
  desc 'check', 'This check is Not Applicable if the SCOM web console is not installed.

From the SCOM web console server, open IIS. Right-click on the Default Website and choose edit bindings. Examine the bindings for the web console and verify that only https is an option. If http is present or if there is no https binding, this is a finding.'
  desc 'fix', 'Issue a web corticated from a trusted internal CA server, as this will be required for https protocols to function properly. It will need to be installed on the server in advance.

From the SCOM web console server, open IIS. 

Right-click on the Default Website and choose edit bindings. 

Click the Add button. 

Under type, select https and enter the appropriate host name in the host name field. 

For the SSL certificate drop down, choose the certificate that was installed. Click OK. 

Test https access to the SCOM web console and troubleshoot if connectivity is not working. 

Once connectivity is established, delete the http binding.'
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40657r643958_chk'
  tag severity: 'high'
  tag gid: 'V-237438'
  tag rid: 'SV-237438r643960_rule'
  tag stig_id: 'SCOM-MA-000001'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-40620r643959_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
