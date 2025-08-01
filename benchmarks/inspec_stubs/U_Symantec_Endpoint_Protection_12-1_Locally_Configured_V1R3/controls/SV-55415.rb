control 'SV-55415' do
  title 'The Symantec Endpoint Protection client Auto-Protect Risk Tracer must be configured to poll network sessions.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infection capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. The scanning for unknown program viruses will mitigate zero day attacks.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Risk Tracer -> Ensure "Poll for network sessions every:" is selected and set to 10000 milliseconds.

Criteria:  If "Poll for network sessions every:" is not selected and set to 10000 milliseconds, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of ThreatTracerSleepMsecs is not set to 10000 milliseconds, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Risk Tracer -> Select "Poll for network sessions every:" and set it to 10000 milliseconds.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48958r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42687'
  tag rid: 'SV-55415r1_rule'
  tag stig_id: 'DTASEP023'
  tag gtitle: 'DTASEP023'
  tag fix_id: 'F-48272r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
