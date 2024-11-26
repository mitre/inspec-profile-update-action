control 'SV-233918' do
  title 'Infoblox DNS servers must protect the authenticity of communications sessions for dynamic updates.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. 

Communication sessions between different DNS clients and servers should employ protections such as DNSSEC or TSIG to validate the integrity of data being transmitted.'
  desc 'check', 'Infoblox Systems can be configured in two ways to limit DDNS client updates.  

For clients that support GSS-TSIG: 
1. Navigate to Data Management >> DNS >> Members tab. 
2. Review each server with the DNS service enabled.  
3. Select each server, click "Edit", toggle Advanced Mode, and select GSS-TSIG.
4. Verify that "Enable GSS-TSIG authentication of clients" is enabled. 
5. When complete, click "Cancel" to exit the "Properties" screen.  

For clients that do not support GSS-TSIG: 1. Navigate to Data Management >> DNS >> Members tab. 
2. Review each server with the DNS service enabled.  
3. Select each server and click "Edit".  
4. Select the "Updates" tab.  
5. Verify that either a Named ACL or set of Access Control Entries (ACEs) is used to limit client DDNS updates.  
6. When complete, click "Cancel" to exit the "Properties" screen.  

If clients that support GSS-TSIG do not have "Enable GSS-TSIG authentication of clients" set or a named ACL or set of ACEs for clients that do not support GSS-TSIG, this is a finding.'
  desc 'fix', 'Infoblox Systems can be configured in two ways to limit DDNS client updates. Refer to the Administrator Guide for detailed instructions.

For clients that support GSS-TSIG: 
1. Navigate to Data Management >> DNS >> Members tab. 
2. Review each server with the DNS service enabled.
3. Select each server, click "Edit", toggle Advanced Mode, and select GSS-TSIG.
4. Configure the option "Enable GSS-TSIG authentication of clients". 
5. Upload the required keys.  
6. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.
7. Perform a service restart if necessary. 

For clients that do not support GSS-TSIG: 
1. Navigate to Data Management >> DNS >> Members tab. 
2. Review each server with the DNS service enabled.  
3. Select each server and click "Edit".  
4. Select the "Updates" tab. 
5. Select an existing Named ACL or configure a new set of ACEs to limit client DDNS.  
6. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
7. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37103r611274_chk'
  tag severity: 'medium'
  tag gid: 'V-233918'
  tag rid: 'SV-233918r621666_rule'
  tag stig_id: 'IDNS-8X-700013'
  tag gtitle: 'SRG-APP-000219-DNS-000029'
  tag fix_id: 'F-37068r611275_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
