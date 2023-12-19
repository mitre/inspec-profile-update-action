control 'SV-254234' do
  title 'Nutanix AOS must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Nutanix AOS is configured to implement nonexecutable data to protect its memory from unauthorized code execution.

$ sudo grep flags /proc/cpuinfo | grep -w nx
flags.       : fpu vme de …. nx pdpe1gb rdtscp...

If "flags" does not contain the "nx" flag, this is a finding.'
  desc 'fix', %q(If Nutanix AOS does not list 'nx' flag in the /proc/cpuinfo and the system's BIOS setup configuration permits toggling the No Execution bit, then set it to "enable".)
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57719r846788_chk'
  tag severity: 'medium'
  tag gid: 'V-254234'
  tag rid: 'SV-254234r846790_rule'
  tag stig_id: 'NUTX-OS-001580'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-57670r846789_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
