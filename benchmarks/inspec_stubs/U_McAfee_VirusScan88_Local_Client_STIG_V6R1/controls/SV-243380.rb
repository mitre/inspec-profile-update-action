control 'SV-243380' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan inside archives.'
  desc 'Malware is often packaged within an archive. In addition, archives might have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', %q(NOTE: This setting must be configured. Exclusions for specific extensions may be created. Exclusions must be documented with, and approved by, the local ISSO/ISSM.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Options:" label. Ensure the "Scan inside archives (e.g. .ZIP)" option is selected.

Criteria:  If "Scan inside archives (e.g. .ZIP)" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the ScanArchives has value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Options:" label. Select the "Scan inside archives (e.g. .ZIP)" option.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46655r722477_chk'
  tag severity: 'medium'
  tag gid: 'V-243380'
  tag rid: 'SV-243380r722479_rule'
  tag stig_id: 'DTAM052'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46612r722478_fix'
  tag 'documentable'
  tag legacy: ['V-6625', 'SV-56423']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
