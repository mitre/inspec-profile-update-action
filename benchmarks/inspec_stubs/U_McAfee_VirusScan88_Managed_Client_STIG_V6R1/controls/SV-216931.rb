control 'SV-216931' do
  title 'McAfee VirusScan On-Access Default Processes Policies must be configured to use only one scanning policy for all processes, unless the use of Low-Risk Processes/High-Risk Processes has been documented with, and approved by, the IAO/IAM.'
  desc 'Organizations should use centrally managed antivirus software that is controlled and monitored regularly by antivirus administrators, who are also typically responsible for acquiring, testing, approving, and delivering antivirus signature and software updates through the organizations. Some processes are known to be higher risk while others are low risk. By restricting policy configuration to the Default Processes policy, all processes will be interpreted equally when applying the policy settings, and will provide the highest level of protection. Best practice dictates configuring Low-Risk and/or High-Risk policies only when it is necessary to improve system performance and will focus the scanning where it is most likely to detect malware. There is risk associated with configuring the Low-Risk and/or High-Risk policies for the purpose of specifically excluding processes from scanning, and should only be done after evaluating other policy settings and determining risk.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Processes tab, locate the "Process Settings:" label. Ensure the "Configure one scanning policy for all processes" option is selected.

Criteria:  If the "Configure one scanning policy for all processes" option is selected, this is not a finding. 
If the "Configure one scanning policy for all processes" option is not selected, and the use of Low-Risk Processes/High-Risk processes has been documented with, and approved by, the IAO/IAM, this is not a finding. 
If the "Configure one scanning policy for all processes" option is not selected, and the use of Low-Risk Processes/High-Risk Processes has not been documented/approved by the IAO/IAM, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value OnlyUseDefaultConfig is 1, this is not a finding. 
If the value is 0 and the use of Low-Risk Processes/High-Risk Processes has not been documented and approved by the IAO/IAM, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Processes tab, locate the "Process Settings:" label. Select the "Configure one scanning policy for all processes" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18161r309522_chk'
  tag severity: 'medium'
  tag gid: 'V-216931'
  tag rid: 'SV-216931r397870_rule'
  tag stig_id: 'DTAM100'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18159r309523_fix'
  tag 'documentable'
  tag legacy: ['SV-55222', 'V-14622']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
