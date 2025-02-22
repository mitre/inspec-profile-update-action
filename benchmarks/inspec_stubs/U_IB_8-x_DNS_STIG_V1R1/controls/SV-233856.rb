control 'SV-233856' do
  title 'The Infoblox system must limit the number of concurrent client connections to the number of allowed dynamic update clients.'
  desc "Limiting the number of concurrent sessions reduces the risk of denial-of-service (DoS) to the DNS implementation. 

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements.

Primary name servers also make outbound connections to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to be made only to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in DoS to legitimate users. Primary name servers should be configured to limit the hosts from which they will accept dynamic updates.

Additionally, the number of concurrent clients, especially TCP clients, needs to be kept to a level that does not risk placing the system in a DoS state."
  desc 'check', 'Infoblox can be configured in two ways to limit DDNS client updates.

1. For clients that support GSS-TSIG, navigate to Data Management >> DNS >> Members tab. 
a. Review each server with the DNS service enabled. 
b. Select each server, click "Edit", toggle Advanced Mode, and select GSS-TSIG. 
c. Verify that "Enable GSS-TSIG authentication of clients" is enabled.

2. For clients that do not support GSS-TSIG, navigate to Data Management >> DNS >> Members tab. 
a. Review each server with the DNS service enabled. Select each server and click "Edit". 
b. Select the "Updates" tab. Verify that either a Named ACL or Set of ACEs are defined to limit client DDNS. 

3. When complete, click "Cancel" to exit the "Properties" screen.  

If "Enable GSS-TSIG authentication of clients" is disabled for clients supporting GSS-TSIG, or a Named ACL or Set of ACEs is not defined to limit DDNS for clients without GSS-TSIG support, this is a finding.'
  desc 'fix', 'Infoblox can be configured in two ways to limit DDNS client updates. Refer to the Administrator Guide for detailed instructions if necessary.

1. For clients that support GSS-TSIG, navigate to Data Management >> DNS >> Members tab. 
a. Review each server with the DNS service enabled. Select each server, click "Edit", toggle Advanced Mode, and select GSS-TSIG. 
b. Configure the option "Enable GSS-TSIG authentication of clients".
c. Upload the required keys.

2. For clients that do not support GSS-TSIG, navigate to Data Management >> DNS >> Members tab. 
a. Review each server with the DNS service enabled. 
b. Select each server and click "Edit". 
c. Select the "Updates" tab. Enable an existing Named ACL or configure a new set of ACEs to limit client DDNS.

3. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
 
4. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37041r611088_chk'
  tag severity: 'medium'
  tag gid: 'V-233856'
  tag rid: 'SV-233856r621666_rule'
  tag stig_id: 'IDNS-8X-100002'
  tag gtitle: 'SRG-APP-000001-DNS-000115'
  tag fix_id: 'F-37006r611089_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
