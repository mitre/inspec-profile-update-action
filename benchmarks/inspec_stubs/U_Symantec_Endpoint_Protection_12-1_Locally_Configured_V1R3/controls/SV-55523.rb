control 'SV-55523' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for handling security risks upon detection must be explicitly configured at the top, Security Risks, level and not be overridden by the Misleading Application sub-level.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. If files are backed up before they are repaired, this could possibly allow the infection to stay on the system.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Select Actions -> Under Security Risk -> Select Misleading Application -> Ensure "Override actions configured for Security Risks" is NOT selected.

Criteria:  If "Override actions configured for Security Risks" is selected, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Expanded

Criteria:  If the value of FirstAction is not 3, this is a finding.
If the value of FirstAction is 3, then check A. A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Expanded\\TCID-14 is 0 or the value is not there, this is not a finding.

64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Expanded

Criteria:  If the value of FirstAction is not 3, this is a finding.
If the value of FirstAction is 3, then check A. A must be compliant for the check to be not a finding.
A - If the value of OverrideDefaultActions within HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}\\Expanded\\TCID-14 is 0 or the value is not there, this is not a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Select Actions -> Under Security Risk -> Select Misleading Application -> Ensure "Override actions configured for Security Risks" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49067r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42795'
  tag rid: 'SV-55523r2_rule'
  tag stig_id: 'DTASEP062'
  tag gtitle: 'DTASEP062'
  tag fix_id: 'F-48381r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
