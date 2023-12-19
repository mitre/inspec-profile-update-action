control 'SV-55513' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan backup option must be disabled to prevent backing up infected files before attempting to repair them.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. If files are backed up before they are repaired, this could possibly allow the infection to stay on the system.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Advanced -> Under Backup options -> Ensure "Back up files before attempting to repair them", is not selected.

Criteria:  If "Back up files before attempting to repair them" is selected, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow632Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}

Criteria:  If the value of BackupToQuarantine is not 0, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Advanced -> Under Backup options -> Ensure "Back up files before attempting to repair them", is not selected.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49057r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42785'
  tag rid: 'SV-55513r1_rule'
  tag stig_id: 'DTASEP051'
  tag gtitle: 'DTASEP051'
  tag fix_id: 'F-48371r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
