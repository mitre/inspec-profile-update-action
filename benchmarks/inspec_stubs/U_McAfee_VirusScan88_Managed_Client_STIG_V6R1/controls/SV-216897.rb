control 'SV-216897' do
  title 'McAfee VirusScan On-Access General Policies must be configured to log the scan sessions.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Reports tab, locate the "Log to file:" label. Ensure the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected.

Criteria:  If the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bLogtoFile is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Reports tab, locate the "Log to file:" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18127r309420_chk'
  tag severity: 'medium'
  tag gid: 'V-216897'
  tag rid: 'SV-216897r397870_rule'
  tag stig_id: 'DTAM009'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18125r309421_fix'
  tag 'documentable'
  tag legacy: ['SV-55145', 'V-6474']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
