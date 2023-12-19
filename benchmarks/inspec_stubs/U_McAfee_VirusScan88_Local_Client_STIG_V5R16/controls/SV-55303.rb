control 'SV-55303' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings actions, When an unwanted program is found must be configured to clean files automatically as first action.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infections capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the "When an unwanted program is found:" label. Ensure for the "Perform this action first:" pull down menu, "Clean files automatically" is selected.

Criteria:  If "Clean files automatically" is selected from "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the uAction_Program does not have a value of 5, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the  "When an unwanted program is found:" label. From the "Perform this action first:" pull down menu, select "Clean files automatically".

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49377r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42575'
  tag rid: 'SV-55303r1_rule'
  tag stig_id: 'DTAM166'
  tag gtitle: 'DTAM166-McAfee VirusScan on-access unwanted program first action'
  tag fix_id: 'F-48157r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
