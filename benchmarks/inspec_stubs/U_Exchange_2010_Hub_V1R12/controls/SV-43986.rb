control 'SV-43986' do
  title 'Internal Receive Connectors must not allow anonymous connections.'
  desc 'This control is used to limit the servers that may use this server as a relay.  If a Simple Mail Transport Protocol (SMTP) sender does not have a direct connection to the Internet (for example, an application that produces reports to be emailed) then it will need to use an SMTP Receive Connector that does have a path to the Internet (for example, a local email server) as a relay.

SMTP relay functions must be protected so third parties are not able to hijack a relay service for their own purposes.  Most commonly, hijacking of relays is done by SPAMMERS to disguise the source of their messages, and may also be used to cover the source of more destructive attacks.  
 
Relays can be restricted in one of three ways; by blocking relays (restrict to a blank list of servers), by restricting use to lists of valid servers, or by restricting use to servers that can authenticate.   Because authenticated connections are the most secure for SMTP Receive Connectors, it is recommended that relays allow only servers that can authenticate.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ReceiveConnector | Select Name, Identity, PermissionGroups

If the value of 'PermissionGroups' is 'AnonymousUsers' for any non-internet connector, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-ReceiveConnector -Identity <'ReceiveConnector'> -PermissionGroups and enter a valid value other than 'AnonymousUsers'."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41672r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33566'
  tag rid: 'SV-43986r1_rule'
  tag stig_id: 'Exch-2-715'
  tag gtitle: 'Exch-2-715'
  tag fix_id: 'F-37458r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
