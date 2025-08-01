control 'SV-44014' do
  title 'Internet facing send Connectors must specify a Smart Host.'
  desc "In the case of identifying a 'Smart Host' for the email environment, a logical send connector is the preferred method.
 
A 'Smart Host' acts as an Internet Facing Concentrator for other email servers. Appropriate hardening can be applied to the Smart Host rather than at multiple locations throughout the enterprise.
 
Failure to identify a 'Smart Host' could default to each email server performing its own lookups (potentially through protective firewalls). Exchange servers should not be Internet facing, and should therefore not perform any 'Smart Host' functions. When the Exchange servers are Internet facing they must, however, be configured to identify the Internet facing server that is performing the 'Smart Host' function."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, SmartHosts

Identify the Internet facing connectors. 

If the value of 'SmartHosts' does not return the Smart Host IP Address, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector <'SendConnector'> -SmartHosts <'IP Address of Smart Host'> -DNSRoutingEnabled $false"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41701r4_chk'
  tag severity: 'medium'
  tag gid: 'V-33594'
  tag rid: 'SV-44014r2_rule'
  tag stig_id: 'Exch-2-771'
  tag gtitle: 'Exch-2-771'
  tag fix_id: 'F-37486r1_fix'
  tag 'documentable'
end
