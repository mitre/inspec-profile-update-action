control 'SV-207300' do
  title 'Exchange Mailbox Stores must mount at startup.'
  desc 'Administrator responsibilities include the ability to react to unplanned maintenance tasks or emergency situations that may require Mailbox data manipulation. Occasionally, there may be a need to start the server with "unmounted" data stores if manual maintenance is being performed on them. Failure to uncheck the "do not mount on startup" condition will result in unavailability of mail services. 

Correct configuration of this control will prevent unplanned outages due to being enabled. When maintenance is being performed, care should be taken to clear the check box upon task completion so mail stores are available to users (unmounted mailbox stores are not available to users).'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, MountAtStartup

If the value of MountAtStartup is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'IdentityName'> -MountAtStartup $true

Note: The <IdentityName> value must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7558r393413_chk'
  tag severity: 'low'
  tag gid: 'V-207300'
  tag rid: 'SV-207300r615936_rule'
  tag stig_id: 'EX13-MB-000170'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-7558r393414_fix'
  tag 'documentable'
  tag legacy: ['SV-84629', 'V-70007']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
