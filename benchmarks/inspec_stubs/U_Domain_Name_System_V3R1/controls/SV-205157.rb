control 'SV-205157' do
  title 'The DNS implementation must limit the number of concurrent sessions for zone transfers to the number of secondary name servers.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation. 

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements.

Primary name servers also make outbound connection to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to only be made to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in DoS to legitimate users. Primary name servers should be configured to limit the hosts from which they will accept dynamic updates.

Additionally, the number of concurrent clients, especially TCP clients, needs to be kept to a level that does not risk placing the system in a DoS state."
  desc 'check', 'Review the DNS server configuration and ensure a limit has been defined for the number of outbound zone transfers to only be allowed to the specified secondary name servers.

If the DNS server configuration does not explicitly specify which hosts to which it sends zone transfers, this is a finding.'
  desc 'fix', 'Configure the DNS primary server to explicitly specify which hosts to which it sends zone transfers.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5424r392387_chk'
  tag severity: 'medium'
  tag gid: 'V-205157'
  tag rid: 'SV-205157r879511_rule'
  tag stig_id: 'SRG-APP-000001-DNS-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-5424r392388_fix'
  tag 'documentable'
  tag legacy: ['SV-69099', 'V-54853']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
