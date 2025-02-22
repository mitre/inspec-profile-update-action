control 'SV-61967' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On Demand scanner must be configured to find potentially unwanted programs.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Advanced" tab, next to "Non-viruses:", verify the check box for "Find potentially unwanted programs" is selected.
Select the check box for "Find joke programs".

If the check box for "Non-viruses: Find potentially unwanted programs" is not selected, this is a finding.
If the check box for "Find joke programs" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

If a task does not exist for the regularly scheduled weekly scan, create a New Client Task to run an On Demand scan at least weekly.

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task. 

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Advanced" tab, next to "Non-viruses:", select the check box for "Find potentially unwanted programs".
Select the check box for "Find joke programs".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49446r2_chk'
  tag severity: 'medium'
  tag gid: 'V-49065'
  tag rid: 'SV-61967r1_rule'
  tag stig_id: 'DTAVSEL-104'
  tag gtitle: 'DTAVSEL-104-McAfee VSEL for SVA ODS scan for PUPs'
  tag fix_id: 'F-49557r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
