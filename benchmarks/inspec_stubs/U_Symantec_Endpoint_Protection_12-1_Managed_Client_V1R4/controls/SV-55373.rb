control 'SV-55373' do
  title 'The Symantec Endpoint Protection client Global Settings Bloodhound heuristic technology must be enabled.'
  desc 'Bloodhound Virus detection scans outgoing email messages and helps to prevent the spread of threats such as worms that can use email clients to replicate and distribute themselves across a network.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Advanced options, select Global Scan Options -> Under Bloodhound Detection Settings -> Ensure "Enable Bloodhound heuristic virus detection" is selected.

Criteria:  If "Enable Bloodhound heuristic virus detection" is not selected, this is a finding. 

Client check:  Locate the Symantec Endpoint Protection icon in the system tray.  Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab -> Under Scan Options -> Ensure "Enable Bloodhound heuristic virus detection" is selected.

Criteria:  If "Enable Bloodhound heuristic virus detection" is not selected, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Advanced options, select Global Scan Options -> Under Bloodhound Detection Settings -> Select "Enable Bloodhound heuristic virus detection".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42645'
  tag rid: 'SV-55373r1_rule'
  tag stig_id: 'DTASEP024'
  tag gtitle: 'DTASEP024'
  tag fix_id: 'F-48229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
