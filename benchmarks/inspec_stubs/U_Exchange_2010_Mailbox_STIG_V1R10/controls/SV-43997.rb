control 'SV-43997' do
  title 'The Public Folder Stores must mount at startup.'
  desc "Administrator responsibilities include the ability to react to unplanned maintenance tasks or emergency situations that may require Public Folder Store data manipulation.  Occasionally, there may be a need to start the server with 'unmounted' data stores,  if manual maintenance is being performed on them.  Failure to uncheck the 'do not mount on startup' condition will result in unavailability of Public Folder services.  

Correct configuration of this control will prevent unplanned outages due to being enabled.  On occasions when it is needed, care should be taken in process steps to clear the checkbox task completion, so that public folder stores are available to users  (unmounted public folder stores are not available to users)."
  desc 'check', "If public folders are not used this check is NA.

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase | Select Name, Identity, MountAtStartup

If the value of 'MountAtStartup' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-PublicFolderDatabase -Identity <'PublicFolderName'> -MountAtStartup $true"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41684r1_chk'
  tag severity: 'low'
  tag gid: 'V-33577'
  tag rid: 'SV-43997r1_rule'
  tag stig_id: 'Exch-1-109'
  tag gtitle: 'Exch-1-109'
  tag fix_id: 'F-37468r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
