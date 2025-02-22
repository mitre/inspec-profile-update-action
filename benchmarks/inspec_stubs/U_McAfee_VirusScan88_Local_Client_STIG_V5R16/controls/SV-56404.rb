control 'SV-56404' do
  title 'McAfee VirusScan On-Demand scan must be configured to decode MIME encoded files.'
  desc 'Multipurpose Internet Mail Extensions (MIME) encoded files can be crafted to hide a malicious payload. When the MIME encoded file is presented to software that decodes the MIME encoded files, such as an email client, the malware is released. Scanning these files as part of the regularly scheduled scans tasks will mitigate this risk.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Options:" label. Ensure the "Decode MIME encoded files" option is selected.

Criteria:  If "Decode MIME encoded files" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the ScanMime has value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Options:" label. Select the "Decode MIME encoded files" option. 


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49318r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6612'
  tag rid: 'SV-56404r1_rule'
  tag stig_id: 'DTAM053'
  tag gtitle: 'DTAM053-McAfee VirusScan decode MIME encoded'
  tag fix_id: 'F-49122r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
