control 'SV-214159' do
  title 'Infoblox systems which perform zone transfers to non-Infoblox Grid DNS servers must be configured to limit the number of concurrent sessions for zone transfers.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation.

Infoblox DNS servers configured in a Grid do not utilize zone transfers; data is replicated using an encrypted management connection. However when a zone contains both Infoblox Grid DNS servers and non-Grid DNS servers a protocol compliant zone transfer is performed.

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements.

Primary name servers also make outbound connection to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to only be made to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in DoS to legitimate users. Primary name servers should be configured to limit the hosts from which they will accept dynamic updates.

Additionally, the number of concurrent clients, especially TCP clients, needs to be kept to a level that does not risk placing the system in a DoS state."
  desc 'check', 'Verify inbound and outbound zone transfer limits are configured. These values control the amount of concurrent zone transfers to non-Grid DNS servers.

Navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.
Select each server, click "Edit", toggle Advanced Mode and select General >> Advanced tab.

Verify zone transfer limitations are configured. If all name servers for all zones utilize a single Infoblox Grid, zone data is transferred via the encrypted Infoblox Grid, this is not a finding.

When complete, click "Cancel" to exit the "Properties" screen.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Members/Servers tab.

Click "Edit" to review each member with the DNS service status of "Running".

Toggle Advanced Mode and select General >> Advanced tab.

Configure both inbound and outbound zone transfer to appropriate values.

When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.3
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15374r295743_chk'
  tag severity: 'low'
  tag gid: 'V-214159'
  tag rid: 'SV-214159r612370_rule'
  tag stig_id: 'IDNS-7X-000010'
  tag gtitle: 'SRG-APP-000001-DNS-000001'
  tag fix_id: 'F-15372r295744_fix'
  tag 'documentable'
  tag legacy: ['SV-83005', 'V-68515']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
