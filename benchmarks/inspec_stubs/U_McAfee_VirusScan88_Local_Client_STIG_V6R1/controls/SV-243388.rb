control 'SV-243388' do
  title 'McAfee VirusScan On-Demand scan log file size must be restricted, but be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.
.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Reports tab, locate the "Log file" label. 

Criteria:  If the "Limit the size of log file" option is selected and the "Maximum log file size:" is at least 10MB, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the bLimitSize value is not 1, this is a finding.
If the uKilobytes is less than 10240 (Decimal), this is a finding.
If the bLimitSize value is 1 and the uKilobytes value is 10240 (Decimal) or more, this is not a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Reports tab, locate the "Log file" label. 
Select the "Limit the size of log file" option.
Under "Maximum log file size:", choose a value of at least 10MB.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46663r722501_chk'
  tag severity: 'medium'
  tag gid: 'V-243388'
  tag rid: 'SV-243388r722503_rule'
  tag stig_id: 'DTAM060'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46620r722502_fix'
  tag 'documentable'
  tag legacy: ['V-6474', 'SV-56371']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
