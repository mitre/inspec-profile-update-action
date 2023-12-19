control 'SV-207287' do
  title 'Exchange Internet-facing Send connectors must specify a Smart Host.'
  desc 'When identifying a "Smart Host" for the email environment, a logical Send connector is the preferred method.

A Smart Host acts as an Internet-facing concentrator for other email servers. Appropriate hardening can be applied to the Smart Host, rather than at multiple locations throughout the enterprise.

Failure to identify a Smart Host could default to each email server performing its own lookups (potentially through protective firewalls). Exchange servers should not be Internet facing and should therefore not perform any Smart Host functions. When the Exchange servers are Internet facing, they must be configured to identify the Internet-facing server that is performing the Smart Host function.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-SendConnector | Select Name, Identity, SmartHosts

Identify the Internet-facing connectors. 

For each Send connector, if the value of SmartHosts does not return the Smart Host IP Address, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-SendConnector  -Identity <'IdentityName'> -SmartHosts <'IP Address of Smart Host'> -DNSRoutingEnabled $false  

Note: The <IdentityName> and <IP Address of Smart Host> values must be in quotes.

Repeat the procedure for each Send connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7545r393374_chk'
  tag severity: 'medium'
  tag gid: 'V-207287'
  tag rid: 'SV-207287r615936_rule'
  tag stig_id: 'EX13-MB-000105'
  tag gtitle: 'SRG-APP-000213'
  tag fix_id: 'F-7545r393375_fix'
  tag 'documentable'
  tag legacy: ['SV-84603', 'V-69981']
  tag cci: ['CCI-001178']
  tag nist: ['SC-20 a']
end
