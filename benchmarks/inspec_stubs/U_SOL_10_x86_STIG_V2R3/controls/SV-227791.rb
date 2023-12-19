control 'SV-227791' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow.  An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it.  This can be designed to cause execution of the data written on the stack.  One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine if the system implements non-executable program stacks.
# grep noexec_user_stack /etc/system

If the noexec_user_stack is not set to 1, this is a finding.'
  desc 'fix', 'This action applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Edit /etc/system and set the noexec_user_stack parameter to 1.  Restart the system for the setting to take effect.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36466r603001_chk'
  tag severity: 'medium'
  tag gid: 'V-227791'
  tag rid: 'SV-227791r603266_rule'
  tag stig_id: 'GEN003540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36430r603002_fix'
  tag 'documentable'
  tag legacy: ['V-11999', 'SV-27412']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
