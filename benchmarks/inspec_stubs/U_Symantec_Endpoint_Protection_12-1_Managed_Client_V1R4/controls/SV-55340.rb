control 'SV-55340' do
  title 'The Symantec Endpoint Protection client must be scheduled to auto update.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The antivirus software product must be configured to receive those updates automatically in order to afford the expected protection.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Under Policies, select LiveUpdate -> Double-click the applied policy -> Select Overview -> Under Policy Name -> Ensure "Enable this policy" is selected.

Criteria:  If "Enable this policy" is not selected, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key:  
32 bit and 64 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\LiveUpdate\\Schedule

Criteria:  If Enabled is not set to 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Under Policies, select LiveUpdate -> Double-click the applied policy -> Select Overview -> Under Policy Name ->  Select "Enable this policy".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42612'
  tag rid: 'SV-55340r1_rule'
  tag stig_id: 'DTASEP004'
  tag gtitle: 'DTASEP004'
  tag fix_id: 'F-48194r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
