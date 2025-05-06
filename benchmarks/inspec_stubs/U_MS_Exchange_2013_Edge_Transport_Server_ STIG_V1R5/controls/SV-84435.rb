control 'SV-84435' do
  title 'Exchange Internet-facing Send connectors must specify a Smart Host.'
  desc 'When identifying a "Smart Host" for the email environment, a logical Send connector is the preferred method.

A Smart Host acts as an Internet-facing concentrator for other email servers. Appropriate hardening can be applied to the Smart Host, rather than at multiple locations throughout the enterprise.

Failure to identify a Smart Host could default to each email server performing its own lookups (potentially through protective firewalls). Exchange servers should not be Internet facing and should therefore not perform any Smart Host functions. When the Exchange servers are Internet facing, they must be configured to identify the Internet-facing server that is performing the Smart Host function.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

If using an Edge Server a Smart Host does not need to be configured, therefore, this is not a finding. 

Determine the Internet-facing connectors.

Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, SmartHosts, DNSRoutingEnabled

For each Send connector, if the value of SmartHosts does not return the Smart Host IP Address and the value for DNSRoutingEnabled is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector <'IdentityName'> -SmartHosts <'IP Address of Smart Host'> -DNSRoutingEnabled $false   

Note: The <IdentityName> value must be in quotes.

Repeat the procedures for each Send connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70265r2_chk'
  tag severity: 'medium'
  tag gid: 'V-69813'
  tag rid: 'SV-84435r2_rule'
  tag stig_id: 'EX13-EG-000080'
  tag gtitle: 'SRG-APP-000213'
  tag fix_id: 'F-76025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001178']
  tag nist: ['SC-20 a']
end
