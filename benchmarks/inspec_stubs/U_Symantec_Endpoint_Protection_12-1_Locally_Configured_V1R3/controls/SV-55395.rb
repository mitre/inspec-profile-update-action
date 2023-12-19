control 'SV-55395' do
  title 'The Symantec Endpoint Protection client Global Settings for Log Retention must be enabled and configured to retain logs for 30 days.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems. (FISMA 800-92)'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab, Log Retention -> Ensure "Delete logs older than" is set to 30 days or greater. 

Criteria:  If "Delete logs older than" is not set to 30 day or greater, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit: 
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV

Criteria:  If the value data for the LogFileRollOverDays values is not 1e (the hex value for 30) or
higher, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab, Log Retention -> Set "Delete logs older than" to 30 days or greater.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48938r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42667'
  tag rid: 'SV-55395r1_rule'
  tag stig_id: 'DTASEP003'
  tag gtitle: 'DTASEP003'
  tag fix_id: 'F-48252r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
