control 'SV-248804' do
  title 'OL 8 must allocate an "audit_backlog_limit" of sufficient size to capture processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter). 
 
Allocating an "audit_backlog_limit" of sufficient size is critical in maintaining a stable boot process. With an insufficient limit allocated, the system is susceptible to boot failures and crashes.

'
  desc 'check', 'Verify OL 8 allocates a sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following commands: 
 
$ sudo grub2-editenv list | grep audit 
 
kernelopts=root=/dev/mapper/ol-root ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82 
 
If the "audit_backlog_limit" entry does not equal "8192" or larger, is missing, or the line is commented out, this is a finding. 
 
Verify "audit_backlog_limit" is set to persist in kernel updates:  
 
$ sudo grep audit /etc/default/grub 
 
GRUB_CMDLINE_LINUX="audit_backlog_limit=8192" 
 
If "audit_backlog_limit" is not set to "8192" or larger or is missing or commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to allocate sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following command: 
 
$ sudo grubby --update-kernel=ALL --args="audit_backlog_limit=8192" 
 
Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates: 
 
GRUB_CMDLINE_LINUX="audit_backlog_limit=8192" 
 
If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient space will need be to be created.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52238r779976_chk'
  tag severity: 'low'
  tag gid: 'V-248804'
  tag rid: 'SV-248804r779978_rule'
  tag stig_id: 'OL08-00-030602'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52192r779977_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
