control 'SV-77563' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must be configured to receive automatic updates.'
  desc 'Anti-virus signature files are updated almost daily by anti-virus software vendors. These files are made available to anti-virus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The anti-virus software product must be configured to receive those updates automatically in order to afford the expected protection.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

Under "View", select "Scheduled Tasks".
Under "Scheduled Tasks", under "Task Summaries", with the assistance of the McAfee VSEL SA, identify the VirusScan DAT update task.
Verify the "Type" is "Update" and the "Status" is "Completed" with Results of "Update Finished".
Under "Task Details" for the task, click on the "Modify" button.
Choose "2. Choose what to update" and verify the "Virus definition files (also known as DAT files)" is selected.

If there is not a task designated as the regularly scheduled DAT Update task, this is a finding.
 
If there exists a task designated as the regularly scheduled DAT Update task, but "Virus definition files (also known as DAT files)" selection under the "2. Choose what to update" section is not selected, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, enter the command "/opt/NAI/LinuxShield/bin/nails task --list".

The command will return a response similar to the following:
LinuxShield configured tasks:
     1  "LinuxShield Update"  (Running)

If the response does not return a configured task for "LinuxShield Update", this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Schedule", select "Product Update".
Under "1. When to update", select "Daily" and choose every "1" day(s), click on "Next".
Under "2. Choose what to update", select "Virus definition files (also known as DAT files), and click on "Next".
Under "3. Enter a task name", give the task a unique task name for the daily update, and click on "Finish".

Configure an /etc/crontab entry for the LinuxShield Update.
To run the Update task manually without the Web interface, access the Linux system being review, either at the console or by a SSH connection.
At the command line, enter the command "/opt/NAI/LinuxShield/bin/nails task -l".
After the task runs, a (Completed) response will be returned.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63073'
  tag rid: 'SV-77563r1_rule'
  tag stig_id: 'DTAVSEL-002'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-68991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
