control 'SV-55149' do
  title 'McAfee VirusScan On-Access General Policies must be configured to log any failure to scan encrypted files.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted. If the data in the log file exceeds the file size set, the oldest 20 percent of the entries are deleted and new data is appended to the file, so although the file size is restricted, it must also be large enough to retain forensic value.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Ensure the "Failure to scan encrypted files" option is selected.

Criteria:  If the "Failure to scan encrypted files" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration 

Criteria:  If the value ReportEncryptedFiles is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Select the "Failure to scan encrypted files" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48780r3_chk'
  tag severity: 'medium'
  tag gid: 'V-6583'
  tag rid: 'SV-55149r1_rule'
  tag stig_id: 'DTAM013'
  tag gtitle: 'DTAM013-McAfee VirusScan log encrypted files parameter'
  tag fix_id: 'F-48007r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
