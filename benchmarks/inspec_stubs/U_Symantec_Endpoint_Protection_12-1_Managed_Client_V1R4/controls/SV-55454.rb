control 'SV-55454' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan backup option must be disabled to prevent backing up infected files before attempting to repair them.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attack mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. If files are backed up before they are repaired, this could possibly allow the infection to stay on the system.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Actions tab, Remediation -> Ensure "Back up files before attempting to repair them" is NOT selected.

Criteria:  If "Back up files before attempting to repair them" is selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow632Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}

Criteria:  If the value of BackupToQuarantine is not 0, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Actions tab, Remediation -> Ensure "Back up files before attempting to repair them" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48998r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42726'
  tag rid: 'SV-55454r1_rule'
  tag stig_id: 'DTASEP051'
  tag gtitle: 'DTASEP051'
  tag fix_id: 'F-48312r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
