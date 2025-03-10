control 'SV-207559' do
  title 'A BIND 9.x master name server must limit the number of concurrent zone transfers between authorized secondary name servers.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation.

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements.

Primary name servers also make outbound connection to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to only be made to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in DoS to legitimate users. Primary name servers should be configured to limit the hosts from which they will accept dynamic updates.

Additionally, the number of concurrent clients, especially TCP clients, needs to be kept to a level that does not risk placing the system in a DoS state."
  desc 'check', 'If this is not a master name server, this requirement is Not Applicable

Verify that the name server is configured to limit the number of zone transfers from authorized secondary name servers.

Inspect the "named.conf" file for the following:

server <ip_address> {
transfers 2;
};

If each "server" statement does not contain a "transfers" sub statement, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file. 

Add the "transfers" sub statement to each "server" statement block.

The value of the "transfers" option can be increased to a value greater than two based on organizational requirements needed to support DNS operations.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7814r283731_chk'
  tag severity: 'medium'
  tag gid: 'V-207559'
  tag rid: 'SV-207559r612253_rule'
  tag stig_id: 'BIND-9X-001070'
  tag gtitle: 'SRG-APP-000001-DNS-000001'
  tag fix_id: 'F-7814r283732_fix'
  tag 'documentable'
  tag legacy: ['SV-87047', 'V-72423']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
