control 'SV-253093' do
  title 'TOSS must implement non-executable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the NX (no-execution) bit flag is set on the system.

Check that the no-execution bit flag is set with the following commands:

$ sudo dmesg | grep NX

[ 0.000000] NX (Execute Disable) protection: active

If "dmesg" does not show "NX (Execute Disable) protection" active, check the cpuinfo settings with the following command: 

$ sudo less /proc/cpuinfo | grep -i flags
flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc

If "flags" does not contain the "nx" flag, this is a finding.'
  desc 'fix', 'The NX bit execute protection must be enabled in the system BIOS.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56546r824949_chk'
  tag severity: 'medium'
  tag gid: 'V-253093'
  tag rid: 'SV-253093r824951_rule'
  tag stig_id: 'TOSS-04-040490'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-56496r824950_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
