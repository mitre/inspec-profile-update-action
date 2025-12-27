control 'SV-207334' do
  title 'Exchange Public Folder Stores must mount at startup.'
  desc 'Administrator responsibilities include the ability to react to unplanned maintenance tasks or emergency situations that may require Public Folder Store data manipulation. Occasionally, there may be a need to start the server with "unmounted" data stores if manual maintenance is being performed on them. Failure to uncheck the "do not mount on startup" condition will result in unavailability of Public Folder services.

Correct configuration of this control will prevent unplanned outages due to being enabled. When maintenance is being performed, care should be taken to clear the check box task completion so public folder stores are available to users (unmounted public folder stores are not available to users).'
  desc 'check', 'If public folders are not used, this check is not applicable.

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase | Select Name, Identity, MountAtStartup

If the value of MountAtStartup is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-PublicFolderDatabase -Identity <'IdentityName'> -MountAtStartup $true

Note: The <IdentityName> value must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7592r393515_chk'
  tag severity: 'low'
  tag gid: 'V-207334'
  tag rid: 'SV-207334r615936_rule'
  tag stig_id: 'EX13-MB-000345'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-7592r393516_fix'
  tag 'documentable'
  tag legacy: ['SV-84679', 'V-70057']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
