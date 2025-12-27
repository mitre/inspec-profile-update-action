control 'SV-243377' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan boot sectors.'
  desc 'Boot sector viruses will install into the boot sector of a system, ensuring that they will execute when the user boots the system. This risk is mitigated by scanning boot sectors at each startup of the system.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, locate the "Scan options:" label. Ensure the "Scan boot sectors" option is selected.

Criteria:  If "Scan boot sectors" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the bSkipBootScan has value of 1, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, find and select the scheduled task that shows a Status of "Daily" or "Weekly" or any frequency other than "Not Scheduled".
Right-click the Task and select Properties.

Under the Scan Locations tab, locate the "Scan options:" label. Select the "Scan boot sectors" option.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46652r722468_chk'
  tag severity: 'medium'
  tag gid: 'V-243377'
  tag rid: 'SV-243377r722470_rule'
  tag stig_id: 'DTAM047'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46609r722469_fix'
  tag 'documentable'
  tag legacy: ['V-6615', 'SV-56409']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
