control 'SV-55302' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to detect unwanted programs.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infections capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "Unwanted programs detection:" label. Ensure the "Detect unwanted programs" option is selected.

Criteria:  If the "Detect unwanted programs" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value ApplyNVP is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "Unwanted programs detection:" label. 

Place a check in the "Detect unwanted programs" checkbox. 

Click OK.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49376r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42574'
  tag rid: 'SV-55302r1_rule'
  tag stig_id: 'DTAM165'
  tag gtitle: 'DTAM165--McAfee VirusScan on-access unwanted programs'
  tag fix_id: 'F-48156r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
