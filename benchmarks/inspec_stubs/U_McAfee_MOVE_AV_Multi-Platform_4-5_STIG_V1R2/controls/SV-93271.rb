control 'SV-93271' do
  title 'The McAfee MOVE AV SVM must have McAfee VirusScan Enterprise installed.'
  desc 'Organizations should deploy anti-virus software on all hosts for which satisfactory anti-virus software is available. Anti-virus software should be installed as soon after OS installation as possible and then updated with the latest signatures and anti-virus software patches (to eliminate any known vulnerabilities in the anti-virus software itself). To support the security of the host, the anti-virus software should be configured and maintained properly so it continues to be effective at detecting and stopping malware. Anti-virus software is most effective when its signatures are fully up to date. Accordingly, anti-virus software should be kept current with the latest signature and software updates to improve malware detection.'
  desc 'check', 'Access the server designated as the McAfee MOVE SVM. In the taskbar, right-click the red McAfee Agent shield and select "About". 

Under "McAfee Agent", ensure "Last agent-to-server communication:" is within the time period designated by the "Agent to Server Communication Interval". 

Ensure the "McAfee VirusScan Enterprise + AntiSpyware Enterprise" is listed as an installed product. 

Ensure the version number is "8.8.0" or higher. 

To use an alternative method for validating: From the ePO server console system tree, select the "Systems tab" and find and click on the asset representing the McAfee MOVE SVM to open its properties. 

Under the "System Properties" tab, ensure the "Last communication" is within the time period designated by the "Agent-to-Server Communication Interval:" under the "McAfee Agent" tab. 

Under the "System Properties" tab, next to the "Installed Products" field, ensure VirusScan Enterprise 8.8.0.x is listed as an installed product. 

Ensure the "Product Version" for VirusScan Enterprise is listed as "8.8.0" or higher. 

If VirusScan Enterprise 8.8.0 or higher is not installed and/or the "Last communication" to the ePO server is not within the specified Agent-to-Server Communication interval, this is a finding.'
  desc 'fix', 'Access the ePO server. From the system tree, select the "Systems" tab and find and click on the asset representing the McAfee MOVE SVM to open its properties. Click on Actions >> Agent >> Modify Tasks on a Single System. 

Click Actions >> New Client Task Assignment. 

Under "Product", select "McAfee Agent".

Under "Task Type", select "Product Deployment".

Under "Task Name", select "Create New Task". 

Next to "Task Name", enter "Deploy VSE to MOVE SVM".
 
Next to "Target Platforms", ensure only Windows is selected. 

In the drop-down box for "Products and components", select "VirusScan Enterprise 8.8.0.x" and ensure the drop-down box for "Action" is set to Install.

Click "Save". 

Click "Next". 

For the "Schedule status:", select "Enabled". 

Configure the schedule variable in accordance with local Change Control policy and click "Next". 

On the "Summary" tab, click "Save" and then "Close". 

Back at the "Systems Information" screen, click on the "Wake Up Agents" button. 

In the "Wake Up McAfee Agent" screen, for the "Force policy update:" settings, select the "Force complete policy and task update" check box. 

Click "OK".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78565'
  tag rid: 'SV-93271r1_rule'
  tag stig_id: 'MV45-SVM-000002'
  tag gtitle: 'MV45-SVM-000002'
  tag fix_id: 'F-85301r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
