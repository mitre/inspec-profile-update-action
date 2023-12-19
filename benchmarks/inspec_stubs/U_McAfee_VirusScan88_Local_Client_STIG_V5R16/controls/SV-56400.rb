control 'SV-56400' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to enable scanning of scripts.'
  desc "Interpreted viruses are executed by an application. Within this subcategory, macro viruses take advantage of the capabilities of applications' macro programming language to infect application documents and document templates, while scripting viruses infect scripts that are understood by scripting languages processed by services on the OS. Many attackers use toolkits containing several different types of utilities and script that can be used to probe and attack hosts. (NIST SP 800-83) The scanning of scripts is crucial in preventing these attacks."
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the ScriptScan tab, locate the "ScriptScan:" label. Ensure the "Enable scanning of scripts" option is selected.

Criteria:  If the "Enable scanning of scripts" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Script Scanner

Criteria:  If the value of ScriptScanEnabled is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the ScriptScan tab, locate the "ScriptScan:" label. Select the "Enable scanning of scripts" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49328r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14618'
  tag rid: 'SV-56400r1_rule'
  tag stig_id: 'DTAM090'
  tag gtitle: 'DTAM090-McAfee VirusScan on-access script scan parameter'
  tag fix_id: 'F-49132r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
