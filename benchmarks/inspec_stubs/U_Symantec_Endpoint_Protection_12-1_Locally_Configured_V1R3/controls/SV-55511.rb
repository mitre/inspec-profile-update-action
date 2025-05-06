control 'SV-55511' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to display a message to the user if a virus is detected.'
  desc "An effective awareness program explains proper rules of behavior for use of an organization's IT systems and information. Accordingly, awareness programs should include guidance to users on malware incident prevention, which can help reduce the frequency and severity of malware incidents.

Organizations should also make users aware of policies and procedures that apply to malware incident handling, such as how to identify if a host may be infected, how to report a suspected incident, and what users need to do to assist with incident handling

Having the antivirus software alert a users when a risk is detected will ensure the user is aware of the incident and will make it possible to more closely relate the incident to any action(s) being performed by the user at the time of the detection."
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Notifications -> Under Detection options -> Ensure "Display a notification message when a risk is detected", is selected.

Criteria:  If "Display a notification message when a risk is detected" is not selected, this is a finding.

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\LocalScans\\{scan ID}

Criteria:  If the value MessageBox is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Notifications -> Under Detection options -> Select "Display a notification message when a risk is detected".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-49055r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42783'
  tag rid: 'SV-55511r2_rule'
  tag stig_id: 'DTASEP049'
  tag gtitle: 'DTASEP049'
  tag fix_id: 'F-48369r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
