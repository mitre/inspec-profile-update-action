control 'SV-45717' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow.  An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it.  This can be designed to cause execution of the data written on the stack.  One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', 'The stock kernel has support for non-executable program stacks compiled in by default.  The kernel build options can be found in the /boot/config-<kernel version>-default file.  Verify that the option was specified when the kernel was built:
# grep –i CONFIG_S390_EXEC /boot/config-<kernel version>-default

The value “CONFIG_S390_EXEC_PROTECT=y” should be returned.  

To activate this support, the “noexec=on” kernel parameter must be specified at boot time.  The message: “Execute protection active, mvcos available” will be written in the boot log when this feature has been configured successfully.  Check for the message with the following command:
# grep –i “execute protect” /var/log/boot.msg
If non-executable program stacks have not been configured, this is a finding.

Verify "randomize_va_space" has not been changed from the default "1" setting.

Procedure:


#sysctl kernel.randomize_va_space
If the return value is not: 
kernel.randomize_va_space = 1
this is a finding.'
  desc 'fix', 'Edit the /etc/zipl.conf file and add “noexec=on” to the parameters line in the stanza for the kernel being used on the system.  Run the ‘zipl’ command to update the boot loader configuration:
# zipl

A system restart is required to implement this change.

Examine /etc/sysctl.conf for the "kernel.randomize_va_space" entry and if found remove it. The system default of "1" enables this module.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11999'
  tag rid: 'SV-45717r1_rule'
  tag stig_id: 'GEN003540'
  tag gtitle: 'GEN003540'
  tag fix_id: 'F-39115r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
