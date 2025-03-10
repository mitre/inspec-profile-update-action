control 'SV-233855' do
  title 'Infoblox systems that perform zone transfers to non-Grid DNS servers must limit the number of concurrent sessions for zone transfers.'
  desc "Limiting the number of concurrent sessions reduces the risk of denial-of-service (DoS) to the DNS implementation.  

Infoblox DNS servers configured in a Grid do not use zone transfers. Data is replicated using an encrypted management connection. However, when a zone contains both Infoblox Grid DNS servers and non-Grid DNS servers, a DNS protocol-compliant zone transfer is performed. Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements.  

Primary name servers also make outbound connection to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to be made only to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in DoS to legitimate users. Primary name servers should be configured to limit the hosts from which they will accept dynamic updates. 

Additionally, the number of concurrent clients, especially TCP clients, needs to be kept to a level that does not risk placing the system in a DoS state."
  desc 'check', 'Verify inbound and outbound zone transfer limits are configured. These values control the amount of concurrent zone transfers to non-Grid DNS servers. 

1. Navigate to Data Management >> DNS >> Members tab. 
2. Review each server with the DNS service enabled.
3. Select each server, click "Edit", toggle Advanced Mode, and select General >> Advanced tab. 
4. Verify zone transfer limitations are configured.
5. When complete, click "Cancel" to exit the "Properties" screen.  

If zone transfer limits are not configured for non-Infoblox grid name servers, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Members tab. 
2. Click "Edit" to review each member with the DNS service status of "Running".
3. Toggle Advanced Mode and select General >> Advanced tab. 
4. Configure both inbound and outbound zone transfer to appropriate values.
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.
6. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37040r611085_chk'
  tag severity: 'medium'
  tag gid: 'V-233855'
  tag rid: 'SV-233855r621666_rule'
  tag stig_id: 'IDNS-8X-100001'
  tag gtitle: 'SRG-APP-000001-DNS-000001'
  tag fix_id: 'F-37005r611086_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
