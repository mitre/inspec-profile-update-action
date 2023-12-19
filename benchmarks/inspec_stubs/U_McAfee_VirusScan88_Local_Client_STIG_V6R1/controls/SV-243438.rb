control 'SV-243438' do
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
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46713r722651_chk'
  tag severity: 'medium'
  tag gid: 'V-243438'
  tag rid: 'SV-243438r722653_rule'
  tag stig_id: 'DTAM165'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46670r722652_fix'
  tag 'documentable'
  tag legacy: ['V-6588', 'SV-56387']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
