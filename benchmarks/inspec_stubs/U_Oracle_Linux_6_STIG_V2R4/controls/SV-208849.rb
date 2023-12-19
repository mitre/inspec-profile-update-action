control 'SV-208849' do
  title 'The system must limit the ability of processes to have simultaneous write and execute access to memory.'
  desc 'A common type of exploit is the stack buffer overflow.  An application receives from an attacker more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it.  This can be designed to cause execution of the data written on the stack.  One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', %q(If the system being evaluated is running a Red Hat-compatible operating system kernel, check that the "kernel.exec-shield" kernel parameter is set to "1" in /etc/sysctl.conf.  If the system is running an Oracle Unbreakable Enterprise kernel, verify that Oracle's Data Execution Prevention is enabled.

First, determine if the system is operating an Oracle Unbreakable Enterprise Kernel (UEK):

# uname -r | grep uek

If no value is returned, the system is running a Red Hat-compatible kernel.  Verify that the "kernel.exec-shield" kernel parameter is set to "1" in the running kernel and /etc/sysctl.conf:

# sysctl kernel.exec-shield
# grep ^kernel\.exec-shield /etc/sysctl.conf | awk -F= '{ print $2 }'
kernel.exec-shield = 1

If there is no value returned, or if a value is returned that is not "1", this is a finding.

If the system was found to be running an Unbreakable Enterprise Kernel, verify that DEP is enabled:

# dmesg | grep 'NX.*protection:'

If there is no value returned, or if a value is returned that is not "NX (Execute Disable) protection: active", this is a finding.

Note that this is not a finding when the underlying processor architecture does not support the "Execute Disable"  (NX) capability.  To determine if the processor supports the NX capability, run the following:

# grep nx /proc/cpuinfo

If there is no value returned, this is not applicable.)
  desc 'fix', %q(If the system being evaluated is running a Red Hat-compatible operating system kernel, then ensure that the "kernel.exec-shield" kernel parameter is set to "1".  If the system is running an Oracle Unbreakable Enterprise Kernel, this parameter does not exist.  When an Unbreakable Enterprise Kernel is booted, Oracle's Data Execution Prevention (DEP) feature will leverage the hardware-enforced NX (never execute) bit of compatible CPUs to protect against code being executed from the stack.  By default, DEP is enabled.  If DEP is not enabled, ensure that the string "noexec=off" does not appear in /boot/grub/grub.conf.

First, determine if the system is operating an Oracle Unbreakable Enterprise Kernel (UEK):

# uname -r | grep uek

If no value is returned, the system is running a Red Hat-compatible kernel.  Edit (or add if necessary) the entry in /etc/sysctl.conf for the "kernel.exec-shield" kernel parameter.  Ensure that this parameter is set to "1" as in:

kernel.exec-shield = 1

If this was not already the default, reboot the system for the change to take effect.

If the system was found to be running an Unbreakable Enterprise Kernel, then ensure that the string "noexec=off" is not found in /boot/grub/grub.conf:

# grep noexec=off /boot/grub/grub.conf

If found, remove the offending kernels from /boot/grub/grub.conf.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9102r357527_chk'
  tag severity: 'medium'
  tag gid: 'V-208849'
  tag rid: 'SV-208849r603263_rule'
  tag stig_id: 'OL6-00-000079'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9102r357528_fix'
  tag 'documentable'
  tag legacy: ['V-50959', 'SV-65165']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
