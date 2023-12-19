control 'SV-243422' do
  title 'McAfee VirusScan Access Protection Rules Anti-Spyware Maximum Protection must be set to block and log execution of scripts from the Temp folder.'
  desc 'This rule prevents the Windows scripting host from running VBScript and JavaScript scripts from the Temp directory. This would protect against a large number of trojans and questionable web installation mechanisms that are used by many adware and spyware applications.'
  desc 'check', 'Note: If the HIPS signature 7035 is enabled to provide this same protection, this check is Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs  >> McAfee >> VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection". Ensure the "Prevent execution of scripts from the Temp folder" (Block and Report) option is selected.

Criteria: If the "Prevent execution of scripts from the Temp folder" (Block and Report) option is selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection". Select the "Prevent execution of scripts from the Temp folder" (Block and Report) option. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46697r722603_chk'
  tag severity: 'medium'
  tag gid: 'V-243422'
  tag rid: 'SV-243422r722605_rule'
  tag stig_id: 'DTAM148'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46654r722604_fix'
  tag 'documentable'
  tag legacy: ['V-14652', 'SV-56394']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
