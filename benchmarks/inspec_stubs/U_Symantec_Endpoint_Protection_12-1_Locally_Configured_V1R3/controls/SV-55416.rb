control 'SV-55416' do
  title 'The Symantec Endpoint Protection client Global Settings Bloodhound heuristic technology must be enabled.'
  desc 'Bloodhound Virus detection scans of outgoing email messages helps to prevent the spread of threats such as worms that can use email clients to replicate and distribute themselves across a network.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab -> Under Scan Options -> Ensure "Enable Bloodhound heuristic virus detection" is selected.

Criteria:  If "Enable Bloodhound heuristic virus detection" is not selected, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab -> Under Scan Options -> Select "Enable Bloodhound heuristic virus detection".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48959r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42688'
  tag rid: 'SV-55416r1_rule'
  tag stig_id: 'DTASEP024'
  tag gtitle: 'DTASEP024'
  tag fix_id: 'F-48273r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
