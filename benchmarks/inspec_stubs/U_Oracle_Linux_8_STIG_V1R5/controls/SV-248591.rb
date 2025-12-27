control 'SV-248591' do
  title 'OL 8 must disable virtual syscalls.'
  desc 'Syscalls are special routines in the Linux kernel, which userspace applications ask to do privileged tasks. Invoking a system call is an expensive operation because the processor must interrupt the currently executing task and switch context to kernel mode and then back to userspace after the system call completes. Virtual syscalls map into user space a page that contains some variables and the implementation of some system calls. This allows the system calls to be executed in userspace to alleviate the context switching expense. 
 
Virtual syscalls provide an opportunity of attack for a user who has control of the return instruction pointer. Disabling vsyscalls help to prevent return-oriented programming (ROP) attacks via buffer overflows and overruns. If the system intends to run containers based on OL 6 components, then virtual syscalls will need enabled so the components function properly.'
  desc 'check', 'Verify that GRUB 2 is configured to disable vsyscalls with the following commands: 
 
$ sudo grub2-editenv list | grep vsyscall 
 
kernelopts=root=/dev/mapper/ol-root ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82 
 
If "vsyscall" is not set to "none" or is missing, this is a finding. 
 
Check that vsyscalls are disabled by default to persist in kernel updates:  
 
$ sudo grep vsyscall /etc/default/grub 
 
GRUB_CMDLINE_LINUX="vsyscall=none" 
 
If "vsyscall" is not set to "none", is missing or commented out and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the use of vsyscalls with the ISSO as an operational requirement or disable them with the following command:
 
$ sudo grubby --update-kernel=ALL --args="vsyscall=none" 
 
Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates: 
 
GRUB_CMDLINE_LINUX="vsyscall=none"'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52025r779337_chk'
  tag severity: 'medium'
  tag gid: 'V-248591'
  tag rid: 'SV-248591r779339_rule'
  tag stig_id: 'OL08-00-010422'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-51979r779338_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
