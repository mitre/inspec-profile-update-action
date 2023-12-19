control 'SV-221245' do
  title 'Exchange internal Receive connectors must not allow anonymous connections.'
  desc 'This control is used to limit the servers that may use this server as a relay. If a Simple Mail Transport Protocol (SMTP) sender does not have a direct connection to the Internet (for example, an application that produces reports to be emailed), it will need to use an SMTP Receive connector that does have a path to the Internet (for example, a local email server) as a relay.

SMTP relay functions must be protected so third parties are not able to hijack a relay service for their own purposes. Most commonly, relay hijacking is done by spammers to disguise the source of their messages and may also be used to cover the source of more destructive attacks.  
 
Relays can be restricted in one of three ways: by blocking relays (restrict to a blank list of servers); by restricting use to lists of valid servers; or by restricting use to servers that can authenticate. Because authenticated connections are the most secure for SMTP Receive connectors, it is recommended that relays allow only servers that can authenticate.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, PermissionGroups

For each Receive connector, if the value of "PermissionGroups" is "AnonymousUsers" for any non-Internet connector, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -PermissionGroups 'valid user group(s)'

Note: The <IdentityName> value and user group(s) must be in single quotes.

Example for user groups only: 'ExchangeServers, ExchangeUsers' 

Repeat the procedures for each Receive connector.

This is an Example only: Set-ReceiveConnector -Identity <'IdentityName'> -PermissionGroups 'ExchangeUsers'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22960r411861_chk'
  tag severity: 'medium'
  tag gid: 'V-221245'
  tag rid: 'SV-221245r612603_rule'
  tag stig_id: 'EX16-ED-000490'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22949r411862_fix'
  tag 'documentable'
  tag legacy: ['SV-95281', 'V-80571']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
