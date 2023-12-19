control 'SV-243405' do
  title 'McAfee VirusScan Buffer Overflow Protection Buffer Overflow Settings must be configured for Protection mode.'
  desc "Buffer overflow is an anomaly where a program, while writing data to a buffer, overruns the buffer's boundary and overwrites adjacent memory. This anomaly has been used maliciously, explicitly to craft exploits. Buffer overflow attacks compose greater than 25% of malware attacks. Without buffer overflow protection enabled, systems are more vulnerable to attacks that attempt to overwrite adjacent memory in the stack frame. Protection mode will ensure buffer overflow is detected and blocked. Otherwise, only a warning message will be logged. Buffer overflow protection is only configurable on non-64-bit systems."
  desc 'check', 'NOTE:  Buffer Overflow Protection is not installed on 64-bit systems; this check would be Not Applicable to 64-bit systems. 

NOTE:  On 32-bit systems, when Host Intrusion Prevention is also installed, Buffer Overflow Protection will show as "Disabled because a Host Intrusion Prevention product is installed"; this check would be Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Buffer Overflow Protection tab, locate the "Buffer Overflow settings:" label. Ensure the "Protection mode" option is selected.

Criteria:  If the "Protection mode" option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking 

Criteria:  If the value BOPMode is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Buffer Overflow Protection tab, locate the "Buffer Overflow settings:" label. Select the "Protection mode" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46680r722552_chk'
  tag severity: 'medium'
  tag gid: 'V-243405'
  tag rid: 'SV-243405r722554_rule'
  tag stig_id: 'DTAM131'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46637r722553_fix'
  tag 'documentable'
  tag legacy: ['V-14657', 'SV-56434']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
