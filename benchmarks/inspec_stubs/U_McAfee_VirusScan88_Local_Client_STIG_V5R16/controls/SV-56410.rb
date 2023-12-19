control 'SV-56410' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to use only one scanning policy for all processes, unless the use of Low-Risk Processes/High-Risk Processes has been documented with, and approved by, the IAO/IAM.'
  desc 'Organizations should use centrally managed antivirus software that is controlled and monitored regularly by antivirus administrators, who are also typically responsible for acquiring, testing, approving, and delivering antivirus signatures and software updates through the organizations. (FISMA SP 800-83) Some processes are known to be higher risk, while others are low risk. By restricting policy configuration to the Default Processes policy, all processes will be interpreted equally when applying the policy settings and will provide the highest level of protection. Best practice dictates configuring Low Risk and/or High Risk policies only when it is necessary to improve system performance, and will focus the scanning where it is most likely to detect malware. There is risk associated with configuring the Low Risk and/or High Risk policies for the purpose of specifically excluding processes from scanning, and should only be done after evaluating other policy settings and determining risk.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Processes tab, ensure the "Configure one scanning policy for all processes" is selected.

Criteria:  If the "Configure one scanning policy for all processes" option is selected, this is not a finding. 
If the "Configure one scanning policy for all processes" option is not selected, and the use of Low-Risk Processes/High-Risk processes has been documented with, and approved by, the IAO/IAM, this is not a finding. 
If the "Configure one scanning policy for all processes" option is not selected, and the use of Low-Risk Processes/High-Risk processes has not been documented/approved by the IAO/IAM, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value OnlyUseDefaultConfig is 1, this is not a finding.
If the value is 0 and  the use of Low-Risk Processes/High-Risk processes has not been documented and approved by the IAO/IAM, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Processes tab, select the "Configure one scanning policy for all processes" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49332r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14622'
  tag rid: 'SV-56410r1_rule'
  tag stig_id: 'DTAM100'
  tag gtitle: 'DTAM100-McAfee VirusScan scan default values'
  tag fix_id: 'F-49136r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
