control 'SV-77515' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to Move infected files to the quarantine directory if first action fails when programs and jokes are found.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the anti-virus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of quarantine will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, under the "When Programs & Jokes are found:", next to "If the above action fails:", verify the "Move infected files to the quarantine directory" radio button is selected.

If, under the "When Programs & Jokes are found:", next to "If the above action fails:", the radio button for "Move infected files to the quarantine directory" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, under the "When Programs & Jokes are found:", next to "If the above action fails:", select the radio button for "Move infected files to the quarantine directory".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63025'
  tag rid: 'SV-77515r1_rule'
  tag stig_id: 'DTAVSEL-016'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
