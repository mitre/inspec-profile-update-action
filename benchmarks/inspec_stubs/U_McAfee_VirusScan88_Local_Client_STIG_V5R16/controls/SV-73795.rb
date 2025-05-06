control 'SV-73795' do
  title 'McAfee VirusScan Access Protection Rules Anti-spyware Maximum Protection must be set to block and report when block execution of all programs from temp folder.'
  desc '<0> [object Object]'
  desc 'check', 'Note:  If the HIPS signatures 7010, 7011, 7020 and 7035 are enabled to provide this same protection, this check is Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection". Ensure the "Prevent all programs from running files from the Temp folder" (Block and Report) option is selected.

Criteria:  If the "Prevent all programs from running files from the Temp folder" (Block and Report) option is selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection".  Select the "Prevent all programs from running files from the Temp folder"(Block and Report) option. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-60141r4_chk'
  tag severity: 'medium'
  tag gid: 'V-59365'
  tag rid: 'SV-73795r3_rule'
  tag stig_id: 'DTAM170'
  tag gtitle: 'DTAM170--Access Protection block execution of all programs from temp folder'
  tag fix_id: 'F-64761r2_fix'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
