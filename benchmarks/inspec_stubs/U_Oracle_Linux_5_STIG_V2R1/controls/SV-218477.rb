control 'SV-218477' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow.  An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it.  This can be designed to cause execution of the data written on the stack.  One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', %q(If the system being evaluated is running a Red Hat compatible operating system kernel, check that the "kernel.exec-shield" kernel parameter is set to "1" in /etc/sysctl.conf.  If the system is running an Oracle Unbreakable Enterprise kernel, verify that Oracle's Data Execution Prevention is enabled.

First, determine if the system is operating an Oracle Unbreakable Enterprise Kernel (UEK):

# uname -r | grep uek

If no value is returned, the system is running a Red Hat compatible kernel.  Verify the "kernel.exec-shield" kernel parameter is set to "1" in /etc/sysctl.conf:

# grep ^kernel\.exec-shield /etc/sysctl.conf | awk -F= '{ print $2 }'
kernel.exec-shield = 1

If there is no value returned or if a value is returned that is not "2", this is a finding.

If the system was found to be running an Unbreakable Enterprise Kernel, verify DEP is enabled:

# dmesg | grep 'NX.*protection:

If there is no value returned or if a value is returned that is not "NX (Execute Disable) protection: active", this is a finding.

Note that this is not a finding when the underlying processor architecture does not support the "Execute Disable"  (NX) capability.  To determine if the processor supports this capability, run the command:

# cat /proc/cpuinfo | grep flags | xargs -n 1 echo | grep -w "nx" | sort -u

If a system's underlying processor supports this functionality, a single entry containing the keyword "nx" will be returned.)
  desc 'fix', %q(If the system being evaluated is running a Red Hat compatible operating system kernel, then ensure that the "kernel.exec-shield" kernel parameter is set to "1".  If the system is running an Oracle Unbreakable Enterprise Kernel, this parameter does not exist.  When an Unbreakable Enterprise Kernel is booted, Oracle's Data Execution Prevention (DEP) feature will leverage the hardware-enforced NX (never execute) bit of compatible CPUs to protect against code being executed from the stack.  By default, DEP is enabled.  If DEP is not enabled, ensure the string "noexec=off" does not appear in /boot/grub/grub.conf.

First, determine if the system is operating an Oracle Unbreakable Enterprise Kernel (UEK):

# uname -r | grep uek

If no value is returned, the system is running a Red Hat compatible kernel.  Edit (or add if necessary) the entry in /etc/sysctl.conf for the "kernel.exec-shield" kernel parameter.  Ensure this parameter is set to "1" as in:

kernel.exec-shield = 1

If this was not already the default, reboot the system for the change to take effect.

If the system was found to be running an Unbreakable Enterprise Kernel, then ensure the string "noexec=off" is not found in /boot/grub/grub.conf:

# grep noexec=off /boot/grub/grub.conf

If found, remove the offending entry and reboot the system for the change to take effect.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19952r562585_chk'
  tag severity: 'medium'
  tag gid: 'V-218477'
  tag rid: 'SV-218477r603259_rule'
  tag stig_id: 'GEN003540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19950r562586_fix'
  tag 'documentable'
  tag legacy: ['V-11999', 'SV-64439']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
