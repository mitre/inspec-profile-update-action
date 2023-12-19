control 'SV-55437' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling malware upon detection must be explicitly configured at the top, Malware, level and not be overridden by sub-levels.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attack mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to delete the file first will prevent the infection from spreading.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Under Malware -> Select Virus -> Ensure "Override actions configured for Malware" is NOT selected.

Criteria:  If "Override actions configured for Malware" is selected, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware

Criteria:  If the value of FirstAction is not 5, this is a finding.
If the value of FirstAction is 5, then check A.  A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware\\TCID-0 is 0 or the value is not there, this is not a finding.

64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware

Criteria:  If the value of FirstAction is not 5, this is a finding.
If the value of FirstAction is 5, then check A.  A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware\\TCID-0 is 0 or the value is not there, this is not a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Under Malware -> Select Virus -> Ensure "Override actions configured for Malware" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42709'
  tag rid: 'SV-55437r1_rule'
  tag stig_id: 'DTASEP055'
  tag gtitle: 'DTASEP055'
  tag fix_id: 'F-48295r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
