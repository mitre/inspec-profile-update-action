control 'SV-44017' do
  title 'The Mailbox Stores must mount at startup.'
  desc "Administrator responsibilities include the ability to react to unplanned maintenance tasks or emergency situations that may require Mailbox data manipulation.  Occasionally, there may be a need to start the server with 'unmounted' data stores,  if manual maintenance is being performed on them.  Failure to uncheck the 'do not mount on startup' condition will result in unavailability of mail services.  

Correct configuration of this control will prevent unplanned outages due to being enabled.  On occasions when it is needed, care should be taken in process steps to clear the check box upon task completion, so that mail stores are available to users (unmounted mailbox stores are not available to users)."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, MountAtStartup

If the value of 'MountAtStartup' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase -Identity <'MailboxName'> -MountAtStartup $true"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41704r1_chk'
  tag severity: 'low'
  tag gid: 'V-33597'
  tag rid: 'SV-44017r1_rule'
  tag stig_id: 'Exch-1-309'
  tag gtitle: 'Exch-1-309'
  tag fix_id: 'F-37489r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
