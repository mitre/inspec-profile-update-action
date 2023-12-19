control 'SV-39504' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow. An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it. This can be designed to cause execution of the data written on the stack. One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', 'On 64-bit systems, verify the sed_config (Stack Execution Disable) setting is "all".

# lsattr -El sys0 -a sed_config

If the second field is not "all", this is a finding.

(32-bit systems do not support sed_config.  This is a permanent finding on 32-bit AIX systems.)'
  desc 'fix', 'Change the sed_config setting to disable stack execution for all processes.

# chdev -l sys0 -a sed_config=all

To assess the impact of updating sed_config, the "all+monitor" setting may be used temporarily.  This temporary update does not mitigate the finding.
Reboot the system for the new setting to take effect.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39050r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11999'
  tag rid: 'SV-39504r1_rule'
  tag stig_id: 'GEN003540'
  tag gtitle: 'GEN003540'
  tag fix_id: 'F-34148r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
