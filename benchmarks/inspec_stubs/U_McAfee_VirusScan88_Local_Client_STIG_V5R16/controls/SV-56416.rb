control 'SV-56416' do
  title 'McAfee VirusScan On-Demand scan must be configured to detect for unwanted programs.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infections capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Options:" label. Ensure the "Detect unwanted programs" option is selected.

Criteria:  If "Detect unwanted programs" option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the ApplyNVP has a value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Options:" label. Select the "Detect unwanted programs" option.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49323r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14654'
  tag rid: 'SV-56416r1_rule'
  tag stig_id: 'DTAM058'
  tag gtitle: 'DTAM058-McAfee VirusScan check unwanted programs'
  tag fix_id: 'F-49127r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
