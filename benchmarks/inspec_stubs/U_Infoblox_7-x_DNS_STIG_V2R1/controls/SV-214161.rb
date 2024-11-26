control 'SV-214161' do
  title 'The Infoblox system must limit the number of concurrent client connections to the number of allowed dynamic update clients.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation.

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements.

Primary name servers also make outbound connections to secondary name servers to provide zone transfers and accept inbound connection requests from clients wishing to provide a dynamic update. Primary name servers should explicitly limit zone transfers to only be made to designated secondary name servers. Because zone transfers involve the transfer of entire zones and use TCP connections, they place substantial demands on network resources relative to normal DNS queries. Errant or malicious frequent zone transfer requests on the name servers of the enterprise can overload the master zone server and result in DoS to legitimate users. Primary name servers should be configured to limit the hosts from which they will accept dynamic updates.

Additionally the number of concurrent clients, especially TCP clients, needs to be kept to a level that does not risk placing the system in a DoS state."
  desc 'check', 'Infoblox Systems can be configured in two ways to limit DDNS client updates.

For clients that support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled. Select each server, click "Edit", toggle Advanced Mode and select GSS-TSIG.
Verify that "Enable GSS-TSIG authentication of clients" is enabled.

For clients that do not support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.
Select each server, click "Edit".
Select the "Updates" tab. 
Verify that either a Named ACL or Set of ACEs are defined to limit client DDNS.
When complete, click "Cancel" to exit the "Properties" screen.

If "Enable GSS-TSIG authentication of clients" is disabled for clients supporting GSS-TSIG or a Named ACL or Set of ACEs are not defined to limit DDNS for clients without GSS-TSIG support, this is a finding.'
  desc 'fix', 'Infoblox Systems can be configured in two ways to limit DDNS client updates.

For clients that support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.
Select each server, click "Edit", toggle Advanced Mode and select GSS-TSIG.
Configure the option "Enable GSS-TSIG authentication of clients".
Upload the required keys.
Refer to the Administration Guide for detailed instructions.

For clients that do not support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.
Select each server, click "Edit".
Select the Updates tab. 
Select either an existing Named ACL or configure a new Set of ACEs to limit client DDNS.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15376r295749_chk'
  tag severity: 'medium'
  tag gid: 'V-214161'
  tag rid: 'SV-214161r612370_rule'
  tag stig_id: 'IDNS-7X-000030'
  tag gtitle: 'SRG-APP-000001-DNS-000115'
  tag fix_id: 'F-15374r295750_fix'
  tag 'documentable'
  tag legacy: ['SV-83009', 'V-68519']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
