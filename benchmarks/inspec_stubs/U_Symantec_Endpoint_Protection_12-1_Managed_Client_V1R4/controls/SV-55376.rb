control 'SV-55376' do
  title 'The Symantec Endpoint Protection client Auto-Protect Scan Actions settings must be explicitly configured at the top, Malware, level and not be overridden by sub-levels.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attack mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to delete the file first will prevent the infection from spreading.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions tab -> Under Actions -> Under Malware -> Select Virus -> Ensure "Override actions configured for Malware" is NOT selected.

Criteria:  If "Override actions configured for Malware" is selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Malware

Criteria:  If the value of FirstAction is not 5, this is a finding.
If the value of FirstAction is 5, then check A.  A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Malware\\TCID-0 is 0 or the value is not there, this is not a finding.

64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Malware

Criteria:  If the value of FirstAction is not 5, this is a finding.
If the value of FirstAction is 5, then check A.  A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Malware\\TCID-0 is 0 or the value is not there, this is not a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions tab -> Under Actions -> Under Malware -> Select Virus -> Ensure "Override actions configured for Malware" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48918r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42648'
  tag rid: 'SV-55376r1_rule'
  tag stig_id: 'DTASEP027'
  tag gtitle: 'DTASEP027'
  tag fix_id: 'F-48232r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
