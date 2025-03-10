control 'SV-77599' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must be configured to run a scheduled On-Demand scan at least once a week.'
  desc 'Anti-virus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks but to ensure all files are frequently scanned, a regularly scheduled full scan will ensure malware missed by the real-time scanning will be detected and mitigated.'
  desc 'check', %q(From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, review tasks under "View", "Scheduled Tasks".
With the System Administrator's assistance, determine which task is intended as the regularly scheduled scan task.
Click on the task and review the details under "Task Details for".

If "Next run" does not specify "every 1 week", or more frequently, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, navigate to /var/opt/NAI/LinuxShield/etc.
Enter the command "/opt/NAI/LinuxShield/bin/nails task --list".

If the return does not show a task for the LinuxShield On-Demand Scan, this is a finding.)
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Schedule", select "On-Demand Scan".
Under "1. When to Scan "select Weekly, Daily or Hourly and indicate day and/or time to regularly execute, and click "Next".
Under "2. What to Scan", enter "/", click "Add".
Click "Next".
Under "3. Choose Scan Settings", select required settings as specified in remaining On-Demand scan requirements, and click "Next".
Under "4. Enter a task name", type a unique name for the task to reflect its frequency, and click "Finish".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63109'
  tag rid: 'SV-77599r1_rule'
  tag stig_id: 'DTAVSEL-100'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-69027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
