control 'SV-44016' do
  title 'Connectivity logging must be enabled.'
  desc 'A connectivity log is a record of the SMTP connection activity of the outbound message delivery queues to the destination Mailbox server, smart host, or domain. Connectivity logging is available on Hub Transport servers and Edge Transport servers. By default, connectivity logging is disabled. If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.

NOTE: Transport configuration settings apply to the organization/global level of the Exchange SMTP path.  By checking and setting them at the Hub server the setting will apply to both Hub and Edge roles.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-TransportServer -Identity <'ServerUnderReview'>  | Select Name, Identity, ConnectivityLogEnabled

If the value of 'ConnectivityLogEnabled' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

 Set-TransportServer -Identity <'ServerUnderReview'> -ConnectivityLogEnabled $true"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33596'
  tag rid: 'SV-44016r1_rule'
  tag stig_id: 'Exch-2-801'
  tag gtitle: 'Exch-2-801'
  tag fix_id: 'F-37488r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
