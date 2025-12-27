control 'SV-55147' do
  title 'McAfee VirusScan On-Access General Policies log file size must be restricted and be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. 

Under the Reports tab, locate the "Log file size:" label. Ensure the "Limit the size of log file" option is selected. Ensure the "Maximum log file size" is at least 10MB.

Criteria:  If the "Limit the size of log file" option is selected and the "Maximum log file size:" is at least 10MB, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bLimitSize is 1 and dwMaxLogSizeMB is configured to Decimal (10) or higher, this is not a finding. 
If bLimitSize is 0, this is a finding.
If dwMaxLogSizeMB is less than Decimal (10), this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Reports tab, locate the "Log file size:" label. Select the "Limit the size of log file" option. For the "Maximum log file size:", input a value of at least 10MB or more. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48778r3_chk'
  tag severity: 'medium'
  tag gid: 'V-6475'
  tag rid: 'SV-55147r1_rule'
  tag stig_id: 'DTAM010'
  tag gtitle: 'DTAM010-McAfee VirusScan limit log size parameter'
  tag fix_id: 'F-48005r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
