control 'SV-55375' do
  title 'The Symantec Endpoint Protection client Global Settings Heuristics Level must be set to Automatic, at a minimum.'
  desc "Heuristics analyzes a program's structure, its behavior, and other attributes for virus-like characteristics. In many cases, it can protect against threats such as mass-mailing worms and macro viruses if they are encountered before updating virus definitions. Advanced heuristics looks for script-based threats in HTML, VBScript, and JavaScript files."
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Advanced options, select Global Scan Options -> Under Bloodhound Detection Settings -> Ensure "Enable Bloodhound heuristic virus detection" is set to Automatic, at a minimum.

Criteria:   If "Enable Bloodhound heuristic virus detection" is not set to Automatic, at a minimum, this is a finding.

Client check:  Locate the Symantec Endpoint Protection icon in the system tray.  Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab -> Under Scan Options ->  Ensure "Enable Bloodhound heuristic virus detection" is set to Automatic at a minimum.

Criteria:  If "Enable Bloodhound heuristic virus detection" is not set to Automatic, at a minimum, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Advanced options, select Global Scan Options -> Under Bloodhound Detection Settings -> Set "Enable Bloodhound heuristic virus detection" to Automatic, at a minimum.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42647'
  tag rid: 'SV-55375r1_rule'
  tag stig_id: 'DTASEP026'
  tag gtitle: 'DTASEP026'
  tag fix_id: 'F-48231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
