control 'SV-55364' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options Automatic enablement setting must be enabled.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Advanced tab -> Under Auto-Protect Reloading and Enablement, When Auto-Protect is disabled -> Ensure "Enable after:" is selected ->  Ensure the time limit is set to 5 minutes  or less.  

Criteria:  If "When Auto-Protect is disabled, enable after:" is not selected, this is a finding. 
If "When Auto-Protect is disabled, enable after:" is selected and the time limit is not set to 5 minutes or less, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of APEOn is not 1 and the value of APESleep is not <= 5, this is a finding. If
APESleep is > 5 or APEOn is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Advanced tab -> Under Auto-Protect Reloading and Enablement, When Auto-Protect is disabled -> Select "Enable after:" -> Set time limit to 5 minutes or less.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42636'
  tag rid: 'SV-55364r1_rule'
  tag stig_id: 'DTASEP016'
  tag gtitle: 'DTASEP016'
  tag fix_id: 'F-48221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
