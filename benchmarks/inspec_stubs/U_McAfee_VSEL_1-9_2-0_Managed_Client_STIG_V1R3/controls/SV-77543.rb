control 'SV-77543' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scanner must be configured to Clean infected files automatically as first action when programs and jokes are found.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the anti-virus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of quarantine will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Actions" tab, next to "When Programs & Jokes are found:", verify the radio button for "Clean infected files automatically" is selected.

If the radio button for "When Programs & Jokes are found: Clean infected files automatically" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Actions" tab, next to "When Programs & Jokes are found:", select the radio button for "Clean infected files automatically".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63053'
  tag rid: 'SV-77543r1_rule'
  tag stig_id: 'DTAVSEL-110'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-68971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
