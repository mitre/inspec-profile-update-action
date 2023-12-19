control 'SV-55304' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings actions, When an unwanted program is found must be configured to delete files automatically if first action fails.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infections capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the "When an unwanted program is found:" label. Ensure from the "If the first action fails, then perform this action:" pull down menu, "Delete files automatically" is selected.

Criteria:  If "Delete files automatically" is selected from "If the first action fails, then perform this action:", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the uSecAction_Program does not have a value of 4, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the  "When an unwanted program is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete files automatically".
Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49378r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42576'
  tag rid: 'SV-55304r1_rule'
  tag stig_id: 'DTAM167'
  tag gtitle: 'DTAM167-McAfee VirusScan on-access unwanted program second action'
  tag fix_id: 'F-48158r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
