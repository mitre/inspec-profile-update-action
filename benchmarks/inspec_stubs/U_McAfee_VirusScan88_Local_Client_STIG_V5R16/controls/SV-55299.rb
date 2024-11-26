control 'SV-55299' do
  title 'McAfee VirusScan On-Delivery Email Scanner must be configured to log session summary and failure to scan encrypted files.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Reports tab, locate the "What to log in addition to scanning activity" label.
Ensure the "Session summary", and "Failure to scan encrypted files", options are both selected.

Criteria: If the "Session summary" and "Failure to scan encrypted files" options are selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ReportOptions

Criteria: If the “dwLogEvent” value is not “0x000001a0 (416)”, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.

Under the “Task” column, select the “On-Delivery Email Scanner” Option, right-click, and select “Properties”.

Under the “Reports” tab, locate the "What to log in addition to scanning activity:" label.

Select the "Session summary" and "Failure to scan encrypted files" options.

Click “OK” to save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49370r4_chk'
  tag severity: 'medium'
  tag gid: 'V-42571'
  tag rid: 'SV-55299r3_rule'
  tag stig_id: 'DTAM159'
  tag gtitle: 'DTAM159-McAfee VirusScan Email on-delivery log session summary'
  tag fix_id: 'F-48153r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
