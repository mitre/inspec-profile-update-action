control 'SV-254158' do
  title 'Nutanix AOS must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Confirm Nutanix AOS generates audit records for all kernel module load, unload, restart actions, and initiations.

$ sudo grep -iw create_module /etc/audit/audit.rules
-a always,exit -F arch=b32 -S create_module -k module-change
-a always,exit -F arch=b64 -S create_module -k module-change

$ sudo grep -iw init_module /etc/audit/audit.rules 
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

$ sudo grep -iw finit_module /etc/audit/audit.rules
-a always,exit -F arch=b32 -S finit_module -k module-change
-a always,exit -F arch=b64 -S finit_module -k module-change

$ sudo grep -iw delete_module /etc/audit/audit.rules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

If both the "b32" and "b64" audit rules are not defined for the module(s) listed syscall, this is a finding.

$ sudo grep -iw kmod /etc/audit/audit.rules
-w /usr/bin/kmod -p x -F auid!=unset -k module-change

If the command does not return any output, this is a finding.

$ sudo cat /boot/grub/grub.conf | grep audit
	kernel /boot/vmlinuz-3.10.0-1160.24.1.el7.nutanix.20210425.cvm.x86_64 ro root=UUID=71a1fe8c-812f-4403-80ed-894f554b061c rd_NO_LUKS rd_NO_LVM rd_NO_MD rd_NO_DM LANG=en_US.UTF-8 SYSFONT=latarcyrheb-sun16 rhgb crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=us audit=1 audit_backlog_limit=8192 nousb fips=1 nomodeset biosdevname=0 net.ifnames=0 scsi_mod.use_blk_mq=y panic=30 console=ttyS0,115200n8 console=tty0 clocksource=tsc kvm_nopvspin=1 xen_nopvspin=1 hv_netvsc.ring_size=512 mds=off mitigations=off

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57643r846560_chk'
  tag severity: 'medium'
  tag gid: 'V-254158'
  tag rid: 'SV-254158r846562_rule'
  tag stig_id: 'NUTX-OS-000540'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57594r846561_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000172']
  tag nist: ['AU-12 a', 'AU-12 c']
end
