control 'SV-233878' do
  title 'The Infoblox DNS server must send outgoing DNS messages from a random port.'
  desc "OS configuration practices as issued by the US Computer Emergency Response Team (US CERT) and the National Institute of Standards and Technology's (NIST's) National Vulnerability Database (NVD), based on identified vulnerabilities that pertain to the application profile into which the name server software fits, should be always followed. 

In particular, hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. In other words, the only allowed incoming ports/protocols to these hosts should be 53/udp and 53/tcp. 

Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker guessing the outgoing message port and sending forged replies."
  desc 'check', 'Verify the default Infoblox configuration to use random ports is not overridden at either the global or member level.  

Global-Level check: 
1. Navigate to Data Management >> DNS Edit Grid DNS Properties, or System DNS Properties on a stand-alone system.  
2. Toggle Advanced Mode and select the General >> Advanced tab. 
3. Verify that the options under "Source Port Settings", "Set static source UDP port for queries (not recommended)", and "Set static source UDP port for notify messages" use the default value of "not enabled".  
4. When complete, click "Cancel" to exit the "Properties" screen.

Member-Level check: 
1. Navigate to Data Management >> DNS >> Members tab.  
2. Review each server with the DNS service enabled.  
3. Select each server, click "Edit", toggle Advanced Mode, and select General >> Advanced tab. 
4. Verify that the options under "Source Port Settings", "Set static source UDP port for queries (not recommended)", and "Set static source UDP port for notify messages" use the default value of "not enabled". 
5. When complete, click "Cancel" to exit the "Properties" screen.  

If configuration of either of these values exists, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS Properties, or System DNS properties on a stand-alone system.  
2. Toggle Advanced Mode and select General >> Advanced tab. Disable "Set static source UDP port for queries (not recommended)" and "Set static source UDP port for notify messages". 
3. Navigate to Data Management >> DNS >> Members tab. 
4. Review each Infoblox member with the DNS service enabled. 
5. Select each server, click "Edit", toggle Advanced Mode, and select General >> Advanced tab. 
6. Locate the section labeled "Source port settings" and click "Override" to use the Grid default values that disable static source ports.  
7. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
8. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37063r611154_chk'
  tag severity: 'medium'
  tag gid: 'V-233878'
  tag rid: 'SV-233878r621666_rule'
  tag stig_id: 'IDNS-8X-400020'
  tag gtitle: 'SRG-APP-000516-DNS-000110'
  tag fix_id: 'F-37028r611155_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
