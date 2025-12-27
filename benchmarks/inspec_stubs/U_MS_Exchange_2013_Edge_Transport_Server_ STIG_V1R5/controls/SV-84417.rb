control 'SV-84417' do
  title 'Exchange Connectivity logging must be enabled.'
  desc 'A connectivity log is a record of the SMTP connection activity of the outbound message delivery queues to the destination mailbox server, smart host, or domain. Connectivity logging is available on Hub Transport servers and Edge Transport servers. By default, connectivity logging is disabled. If events are not recorded, it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.

NOTE: Transport configuration settings apply to the organization/global level of the Exchange SMTP path. By checking and setting them at the Hub server, the setting will apply to both Hub and Edge roles.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportService | Select Name, Identity, ConnectivityLogEnabled

If the value of ConnectivityLogEnabled is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-TransportService -Identity <'IdentityName'> -ConnectivityLogEnabled $true

Note: The <IdentityName> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69795'
  tag rid: 'SV-84417r1_rule'
  tag stig_id: 'EX13-EG-000035'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-76007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
