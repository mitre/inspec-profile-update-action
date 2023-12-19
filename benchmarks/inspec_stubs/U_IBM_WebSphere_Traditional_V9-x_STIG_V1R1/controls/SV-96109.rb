control 'SV-96109' do
  title 'The WebSphere Application Server plugin must be configured to use HTTPS only.'
  desc 'The Web server plug-in transmits information from the Web server to the Web container over HTTP by default. Extra steps must be taken to protect the traffic from the Web server to the Web container. To force the use of HTTPS for all traffic from the plug-in, disable the HTTP transport from the Web container on every application server and then regenerate and deploy the plug-in. WCInboundDefault and the HttpQueueInboundDefault transport chains must be disabled. At which time the plug-in can only use HTTPS and so it will use it for all traffic regardless of how the traffic arrived at the Web container.'
  desc 'check', 'From the admin console, navigate to Servers >> Server Types >> WebSphere Application Servers >> select each server (server name) >> Web Container Settings >> Web container transport chains. 

Verify both "WCInboundDefault" and the "HttpQueueInboundDefault" transport chains are disabled.

If they are not disabled, this is a finding.'
  desc 'fix', 'From the admin console, navigate to Servers >> Server Types >> WebSphere Application Servers >> select each server (server name) >> Web Container Settings >> Web container transport chains. 

Select the "WCInboundDefault" and the "HttpQueueInboundDefault" transport chains and disable them.

Click "Apply".

Click "Save".

Restart the DMGR and resynch the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81395'
  tag rid: 'SV-96109r1_rule'
  tag stig_id: 'WBSP-AS-001630'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-88181r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
