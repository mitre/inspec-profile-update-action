control 'SV-55396' do
  title 'The Symantec Endpoint Protection client must be scheduled to auto update.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The antivirus software product must be configured to receive those updates automatically in order to afford the expected protection.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Client Management -> Select Configure Settings -> Under the LiveUpdate tab -> Ensure "Enable automatic updates" is selected.

Criteria:  If "Enable automatic updates" is not selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit and 64 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\LiveUpdate\\Schedule

Criteria:  If Enabled is not set to 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Client Management -> Select Configure Settings -> Under the LiveUpdate tab -> Select "Enable automatic updates ".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48939r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42668'
  tag rid: 'SV-55396r1_rule'
  tag stig_id: 'DTASEP004'
  tag gtitle: 'DTASEP004'
  tag fix_id: 'F-48253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
