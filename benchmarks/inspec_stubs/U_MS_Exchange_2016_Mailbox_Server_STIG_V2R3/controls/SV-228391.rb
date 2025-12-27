control 'SV-228391' do
  title 'Exchange Internal Receive connectors must not allow anonymous connections.'
  desc 'This control is used to limit the servers that may use this server as a relay. If a Simple Mail Transport Protocol (SMTP) sender does not have a direct connection to the Internet (for example, an application that produces reports to be emailed), it will need to use an SMTP Receive connector that does have a path to the Internet (for example, a local email server) as a relay.

SMTP relay functions must be protected so third parties are not able to hijack a relay service for their own purposes. Most commonly, hijacking of relays is done by spammers to disguise the source of their messages and may also be used to cover the source of more destructive attacks.
 
Relays can be restricted in one of three ways: by blocking relays (restrict to a blank list of servers), by restricting use to lists of valid servers, or by restricting use to servers that can authenticate. Because authenticated connections are the most secure for SMTP Receive connectors, it is recommended that relays allow only servers that can authenticate.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, PermissionGroups

For each Receive connector, if the value of "PermissionGroups" is "AnonymousUsers" for any receive connector, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'IdentityName'> -PermissionGroups and enter a valid value user group. 

Note: The <IdentityName> value must be in single quotes.

Example: Set-ReceiveConnector -Identity <'IdentityName'> -PermissionGroups ExchangeUsers

Repeat the procedures for each Receive connector."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30624r496969_chk'
  tag severity: 'medium'
  tag gid: 'V-228391'
  tag rid: 'SV-228391r612748_rule'
  tag stig_id: 'EX16-MB-000470'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30609r496970_fix'
  tag 'documentable'
  tag legacy: ['SV-95407', 'V-80697']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
