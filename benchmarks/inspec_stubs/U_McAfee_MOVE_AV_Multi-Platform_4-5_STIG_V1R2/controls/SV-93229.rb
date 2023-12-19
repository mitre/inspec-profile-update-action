control 'SV-93229' do
  title 'The McAfee VirusScan Enterprise Access Protection rules must be used for self-protection of the files and folder of the McAfee Security Virtual Manager (SVM).'
  desc 'The VirusScan Enterprise Access Protection rules will defend files, services, and registry keys on the McAfee Security Virtual Manager (SVM).'
  desc 'check', %q(The McAfee MOVE AV [Multi-Platform] SVM does not have a built-in protection mechanism. In order to protect the McAfee MOVE AV [Multi-Platform] SVM's files, services, and registry keys, the McAfee VirusScan Enterprise Access Protection features are used. 

From the ePO server console System Tree, select the Systems tab, find and click on the asset representing the McAfee MOVE SVM to open its properties, select "Actions", select "Agent", and select "Modify Policies on a Single System". 

From the product drop-down list, select "VirusScan Enterprise 8.8.x". Click on the "Access Protection Policies" policy to open the properties. From the "Settings for:" drop-down list, select "Server". 

In the "Access protection rules:" settings, under "Categories", click to select the "User-defined Rules". 

Under "Block/Report/Rules", ensure rules are configured for McAfee MOVE SVM protection. 

If multiple User-defined rules are created, consult with the System Administration to determine the rules for the purpose of this requirement. 

For the File/Folder Access Protection rule created to protect the MOVE AV Server folder, ensure both the "Block" and "Report" check boxes are selected. 

Select the rule and click "Edit". 

Ensure the path to which the McAfee MOVE SVM has been installed (default is C:\Program Files (x86)\McAfee\MOVE AV Server\**) is reflected in the "File or folder name to block:" section. 

Ensure "Write access to files", "New files being created", and "Files being deleted" are selected under the "File actions to prevent:" section. 

If a File/Folder Blocking rule does not exist to protect the path to which the McAfee MOVE SVM Server has been installed (default is C:\Program Files (x86)\McAfee\MOVE AV Server), this is a finding. 

On the system designated as the McAfee MOVE SVM Server, access the local McAfee VirusScan Enterprise Console. 

Under the "Task" column, right-click on "Access Protection", select "Properties". 

In the "Access protection rules:" settings, under "Categories", click "User-defined Rules". 

Under "Block/Report/Rules", ensure rules are configured for McAfee MOVE SVM protection. 

If multiple User-defined rules are created, consult with the System Administration to determine the rules for the purpose of this requirement. 

For the File/Folder Access Protection rule created to protect the MOVE AV Server folder, ensure both the "Block" and "Report" check boxes are selected. 

Select the rule, click "Edit". 

Ensure "mvserver.exe" is reflected under the "Processes to exclude:" section. 

Ensure the path to which the McAfee MOVE SVM has been installed (default is C:\Program Files (x86)\McAfee\MOVE AV Server\**) is reflected in the "File or folder name to block:" section. 

Ensure "Write access to files", "New files being created", and "Files being deleted" are selected under the "File actions to prevent:" section. 

If a File/Folder Blocking rule does not exist to protect the path to which the McAfee MOVE SVM Server has been installed (default is C:\Program Files (x86)\McAfee\MOVE AV Server), this is a finding.

In the "Access protection rules:" settings, under "Categories", click "User-defined Rules".

Under "Block/Report/Rules", ensure rules are configured for registry protection for the following registry paths:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvserver
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvserver\Parameters
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvserver\Parameters\ODS

If a registry protection rule does not exist to protect the specified registry paths, this is a finding.)
  desc 'fix', %q(The McAfee MOVE AV [Multi-Platform] SVM does not have a built-in protection mechanism. In order to protect the McAfee MOVE AV [Multi-Platform] SVM's files, services, and registry keys, the McAfee VirusScan Enterprise Access Protection features are used. 

From the ePO server console System Tree, select the "Systems" tab, find and click on the asset representing the McAfee MOVE SVM to open its properties, select "Actions", select "Agent", and select "Modify Policies on a Single System". 

From the product drop-down list, select "VirusScan Enterprise 8.8.x". Click "Access Protection Policies" policy to open the properties. From the "Settings for:" drop-down list, select "Server". 

In the "Access protection rules:" settings, under "Categories", click "User-defined Rules", click "New". 

Choose "File/Folder Blocking Rule" to create the rule identified as the File protection rule. Specify an appropriate Rule name: (i.e., McAfee MOVE SVM File and Folder Protection). 

Enter the path to which the McAfee MOVE SVM has been installed (default is C:\Program Files (x86)\McAfee\MOVE AV Server\**) in the "File or folder name to block:" section. 

Select the "Write access to files", "New files being created", and "Files being deleted" under the "File actions to prevent:" section. Click "OK". 

After the rule is created, select the "Block" and "Report" check boxes. 

Click "Save".

Configure an additional rule for the registry protection of the following registry paths:

Under "Block/Report/Rules", ensure rules are configured for registry protection for the following registry paths:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvserver
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvserver\Parameters
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvserver\Parameters\ODS)
  impact 0.7
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78085r1_chk'
  tag severity: 'high'
  tag gid: 'V-78523'
  tag rid: 'SV-93229r1_rule'
  tag stig_id: 'MV45-GEN-000004'
  tag gtitle: 'MV45-GEN-000004'
  tag fix_id: 'F-85257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
