control 'SV-248589' do
  title 'OL 8 must implement non-executable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism. 
 
Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the NX (no-execution) bit flag is set on the system with the following commands: 
 
$ sudo dmesg | grep NX 
 
[ 0.000000] NX (Execute Disable) protection: active 
 
If "dmesg" does not show "NX (Execute Disable) protection" active, check the "cpuinfo" settings with the following command: 
 
$ sudo less /proc/cpuinfo | grep -i flags 
flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc 
 
If "flags" does not contain the "nx" flag, this is a finding.'
  desc 'fix', 'Enable the NX bit execute protection in the system BIOS.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52023r779331_chk'
  tag severity: 'medium'
  tag gid: 'V-248589'
  tag rid: 'SV-248589r853770_rule'
  tag stig_id: 'OL08-00-010420'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-51977r779332_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
