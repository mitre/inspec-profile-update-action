control 'SV-243383' do
  title 'McAfee VirusScan On-Demand scan must be configured to find unknown macro threats.'
  desc "Interpreted viruses are executed by an application. Within this subcategory, macro viruses take advantage of the capabilities of applications' macro programming language to infect application documents and document templates, while scripting viruses infect scripts that are understood by scripting languages processed by services on the OS. Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. The scanning for unknown macro viruses will mitigate zero day attacks."
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Ensure the "Find unknown macro threats" option is selected.

Criteria:  If "Find unknown macro threats" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the dwMacroHeuristicsLevel has value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Select the "Find unknown macro threats" option.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46658r722486_chk'
  tag severity: 'medium'
  tag gid: 'V-243383'
  tag rid: 'SV-243383r722488_rule'
  tag stig_id: 'DTAM055'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46615r722487_fix'
  tag 'documentable'
  tag legacy: ['V-42565', 'SV-55293']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
