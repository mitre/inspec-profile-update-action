control 'SV-55341' do
  title 'The Symantec Endpoint Protection client Tamper Protection must be configured to block attempts to tamper with or shut down the client.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans and other malware infecting the system during that startup phase."
  desc 'check', 'Server check: From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Clients -> Under Clients -> Select the client to be checked -> Under the Policies tab, Settings -> Select General Settings -> Under the Tamper Protection tab -> Ensure "Protect Symantec security software from being tampered with or shut down" is selected.

Criteria:  If "Protect Symantec security software from being tampered with or shut down" is not selected, this is a finding.

Client check:  Locate the Symantec Endpoint Protection icon in the system tray.  Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Client Management -> Select Configure Settings -> Under the Tamper Protection tab -> Ensure "Protect Symantec security software from being tampered with or shut down" is selected.

Criteria:  If "Protect Symantec security software from being tampered with or shut down" is not selected, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Clients -> Under Clients -> Select the client to be checked -> Under the Policies tab, Settings -> Select General Settings -> Under the Tamper Protection tab -> Select "Protect Symantec security software from being tampered with or shut down".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42613'
  tag rid: 'SV-55341r1_rule'
  tag stig_id: 'DTASEP005'
  tag gtitle: 'DTASEP005'
  tag fix_id: 'F-48195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001248']
  tag nist: ['SI-3 (3)']
end
