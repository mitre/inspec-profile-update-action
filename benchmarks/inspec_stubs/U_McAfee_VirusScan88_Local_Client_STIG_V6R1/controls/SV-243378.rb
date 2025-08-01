control 'SV-243378' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan all files.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "File types to scan:" label. Ensure the "All files" option is selected.

Criteria:  If "All files" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria: If, under the applicable GUID key, the bScanAllFiles has value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Item tab, locate the "File types to scan:" label. Select the "All files" option. 


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46653r722471_chk'
  tag severity: 'medium'
  tag gid: 'V-243378'
  tag rid: 'SV-243378r722473_rule'
  tag stig_id: 'DTAM048'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46610r722472_fix'
  tag 'documentable'
  tag legacy: ['V-6618', 'SV-56422']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
