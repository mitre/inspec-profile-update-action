control 'SV-61933' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 On-Access scanner must be configured to Clean infected files automatically as first action when programs and jokes are found.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, next to "When Programs & Jokes are found:", verify the radio button for "Clean infected files automatically" is selected.

If, next to "When Programs & Jokes are found:", the radio button for "Clean infected files automatically" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System.  From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Actions" tab, next to "When Programs & Jokes are found:", select the radio button for "Clean infected files automatically".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-50127r3_chk'
  tag severity: 'medium'
  tag gid: 'V-49047'
  tag rid: 'SV-61933r1_rule'
  tag stig_id: 'DTAVSEL-015'
  tag gtitle: 'DTAVSEL-015-McAfee VSEL for SVA OAS PUPS first action'
  tag fix_id: 'F-52383r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
