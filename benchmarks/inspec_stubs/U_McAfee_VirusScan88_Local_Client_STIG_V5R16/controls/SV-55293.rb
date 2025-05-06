control 'SV-55293' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan memory for rootkits.'
  desc 'A rootkit is a stealthy type of software, usually malicious, and is designed to mask the existence of processes or programs from normal methods of detection. Rootkits will often enable continued privileged access to a computer. Scanning and handling detection of rootkits will mitigate the likelihood of rootkits being installed and used maliciously on the system.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, in the box under the "Specify where scanning takes place." label, ensure the "Memory for rootkits" option is displayed.

Criteria:  If "Memory for rootkits" is displayed in the in the configuration for the daily or weekly On-Demand Scan, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on demand client scan task. 

Criteria:  If, under the applicable GUID key, there exists a szScanItem with a REG_SZ value of "SpecialScanForRootkits", this is not a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, in the box under the "Specify where scanning takes place." label, select "Memory for rootkits" from the drop-down selection box.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-48878r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42565'
  tag rid: 'SV-55293r1_rule'
  tag stig_id: 'DTAM154'
  tag gtitle: 'DTAM154-McAfee VirusScan on-demand memory rootkits'
  tag fix_id: 'F-48147r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
