control 'SV-27414' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow.  An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it.  This can be designed to cause execution of the data written on the stack.  One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'fix', 'Examine /etc/sysctl.conf for "kernel.exec-shield" and "kernel.randomize_va_space" entries and if found remove them. The system default of "1" enables these modules.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11999'
  tag rid: 'SV-27414r1_rule'
  tag stig_id: 'GEN003540'
  tag gtitle: 'GEN003540'
  tag fix_id: 'F-24686r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
