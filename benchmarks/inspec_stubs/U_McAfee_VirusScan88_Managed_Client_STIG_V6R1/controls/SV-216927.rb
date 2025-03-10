control 'SV-216927' do
  title 'McAfee VirusScan On-Access General Policies must be configured to enable scanning of scripts.'
  desc "Interpreted viruses are executed by an application. Within this subcategory, macro viruses take advantage of the capabilities of applications' macro programming language to infect application documents and document templates, while scripting viruses infect scripts that are understood by scripting languages processed by services on the OS. Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. (NIST SP 800-83) The scanning of scripts is crucial in preventing these attacks."
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the ScriptScan tab, locate the "ScriptScan:" label. Ensure the "Enable scanning of scripts" option is selected.

Criteria:  If the "Enable scanning of scripts" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Script Scanner

Criteria:  If the value of ScriptScanEnabled is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the ScriptScan tab, locate the "ScriptScan:" label. Select the "Enable scanning of scripts" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18157r309510_chk'
  tag severity: 'medium'
  tag gid: 'V-216927'
  tag rid: 'SV-216927r397870_rule'
  tag stig_id: 'DTAM090'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18155r309511_fix'
  tag 'documentable'
  tag legacy: ['SV-55214', 'V-14618']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
