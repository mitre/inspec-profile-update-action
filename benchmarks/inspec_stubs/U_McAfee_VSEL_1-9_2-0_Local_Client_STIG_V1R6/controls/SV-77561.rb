control 'SV-77561' do
  title 'The anti-virus signature file age must not exceed 7 days.'
  desc 'Anti-virus signature files are updated almost daily by anti-virus software vendors. These files are made available to anti-virus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. By configuring a system to attempt an anti-virus update on a daily basis, the system is ensured of maintaining an anti-virus signature age of 7 days or less. If the update attempt were to be configured for only once a week, and that attempt failed, the system would be immediately out of date.'
  desc 'check', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "View", select "Host Summary".
In the "Host Summary", verify the "DAT Date:" is within the last 7 days.

If the "DAT Date:" is not within the last 7 days, this is a finding.

To validate without the Web interface, access the Linux system being reviewed, either at the console or by a SSH connection.
At the command line, enter the command "ls -lt /opt/NAI/LinuxShield/engine/dat".

The command will return a listing of the avvclean.dat, avvnames.dat and avvscan.dat files. If their respective file dates are not within the last 7 days, this is a finding.'
  desc 'fix', 'From a desktop browser window, connect to the McAfee VirusScan Enterprise for Linux (VSEL) Monitor (WEB interface) of the Linux system being reviewed and logon with the nails user account.

In the VSEL WEB Monitor, under "Schedule", select "Product Update".
Under "When to update", select the "Immediately" radio button, and click on "Next".
Under "Choose what to update", select "Virus definition files (also known as DAT files)", click on "Next".
Under "Enter a task name", type a unique name for this task, and click on "Finish".

Re-validate anti-virus signature file age.
To run the Update task manually without the Web interface, access the Linux system being review, either at the console or by a SSH connection.
Add a task to /etc/crontab to run the nails updater.
At the command line, enter the command "/opt/NAI/LinuxShield/bin/nails task -l".
After the task runs, a (Completed) response will be returned.'
  impact 0.7
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63823r1_chk'
  tag severity: 'high'
  tag gid: 'V-63071'
  tag rid: 'SV-77561r1_rule'
  tag stig_id: 'DTAVSEL-001'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-68989r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
