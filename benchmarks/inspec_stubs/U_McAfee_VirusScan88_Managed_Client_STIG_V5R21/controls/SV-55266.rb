control 'SV-55266' do
  title 'McAfee VirusScan On-Delivery Email Scan Policies must be configured to log session summary and failure to scan encrypted files.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Reports tab, locate the "What to log in addition to scanning activity" label. Ensure the "Session summary", and "Failure to scan encrypted files" options are selected. 

Criteria: If the "Session summary" and "Failure to scan encrypted files" options are selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\McAfee\\ (32-bit) 
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit) 
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ReportOptions 

Criteria: If the value dwLogEvent is not x120 (288) or x130 (304), this is a finding.  
x120 (288) indicates both Session summary and Failure to scan encrypted files are selected. 
x130 (304) indicates Session summary, Failure to scan encrypted files, and Session settings are all selected.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Select the "Session summary" and "Failure to scan encrypted files" options. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48856r5_chk'
  tag severity: 'medium'
  tag gid: 'V-42538'
  tag rid: 'SV-55266r4_rule'
  tag stig_id: 'DTAM159'
  tag gtitle: 'DTAM159-McAfee VirusScan Email on-delivery log session summary'
  tag fix_id: 'F-48120r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
