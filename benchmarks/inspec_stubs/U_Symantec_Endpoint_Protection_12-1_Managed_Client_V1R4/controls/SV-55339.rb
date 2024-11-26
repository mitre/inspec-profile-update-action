control 'SV-55339' do
  title 'The Symantec Endpoint Protection client Global Settings for Log Retention must be enabled and configured to retain logs for 30 days.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems. (FISMA 800-92)'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Advanced Options -> Select Miscellaneous -> Select the Log Handling tab -> Under Log Retention -> Ensure "Delete logs older than" is set to 30 days or greater.                                                

Criteria: If "Delete logs older than" is not set to 30 days or greater, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key:
32 bit: 
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV

Criteria:  If the value data for the LogFileRollOverDays values is not 1e (the hex value for 30) or
higher, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click on the applied policy -> Under Windows Settings, Advanced Options -> Select Miscellaneous -> Select the Log Handling tab -> Under Log Retention -> Set "Delete logs older than" to 30 days or greater.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48892r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42611'
  tag rid: 'SV-55339r1_rule'
  tag stig_id: 'DTASEP003'
  tag gtitle: 'DTASEP003'
  tag fix_id: 'F-48193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
