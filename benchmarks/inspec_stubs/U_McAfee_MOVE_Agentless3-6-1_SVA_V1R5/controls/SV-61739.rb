control 'SV-61739' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to detect unwanted programs.'
  desc 'Due to the ability of malware to mutate after infection, standard antivirus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is Heuristic detection.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "Unwanted programs detection:", verify the checkbox for "Detect unwanted programs" is selected.
In the Scan Items tab of the Policy Settings, next to the "Unwanted programs detection:", verify the checkboxes for "Spyware", "Adware", "Remote Administration Tools", "Dialers", "Password Crackers", "Jokes", "Key Loggers", and "Other Potentially Unwanted Programs" are all selected.

If the checkbox for "Unwanted programs detection: Detect unwanted programs", and/or the checkbox for any of "Spyware", "Adware", "Remote Administration Tools", "Dialers", "Password Crackers", "Jokes", "Key Loggers", and "Other Potentially Unwanted Programs" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "Unwanted programs detection:", select the checkbox for "Detect unwanted programs".
In the Scan Items tab of the Policy Settings, next to the "Unwanted programs detection:", select the checkboxes for "Spyware", "Adware", "Remote Administration Tools", "Dialers", "Password Crackers", "Jokes", "Key Loggers", and "Other Potentially Unwanted Programs".

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49466r5_chk'
  tag severity: 'medium'
  tag gid: 'V-48861'
  tag rid: 'SV-61739r2_rule'
  tag stig_id: 'AV-MOVE-SVA-112'
  tag gtitle: 'AV-MOVE-SVA-112-McAfee MOVE detect unwanted programs.'
  tag fix_id: 'F-49578r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
