control 'SV-35009' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow. An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it. This can be designed to cause execution of the data written on the stack. One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', %q(Determine if the system implements non-executable program stacks.
# kctune | grep -i "executable_stack" | tr '\011' ' ' | tr -s ' ' | \
	sed -e 's/^[  \t]*//' | cut -f 2,2 -d " "

If the executable_stack tunable is set to 1, this is a finding.)
  desc 'fix', '# kctune executable_stack=0

The system will require a restart/reboot for the setting to take effect.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36498r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11999'
  tag rid: 'SV-35009r1_rule'
  tag stig_id: 'GEN003540'
  tag gtitle: 'GEN003540'
  tag fix_id: 'F-31853r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1, ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
