control 'SV-248803' do
  title 'OL 8 must enable auditing of processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter). 
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 
 
DoD has defined the list of events for which OL 8 will provide an audit record generation capability as the following: 
 
1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels); 
 
2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; 
 
3) All account creations, modifications, disabling, and terminations; and 
 
4) All kernel module load, unload, and restart actions.

'
  desc 'check', 'Verify OL 8 enables auditing of processes that start prior to the audit daemon with the following commands:

$ sudo grub2-editenv list | grep audit

kernelopts=root=/dev/mapper/ol-root ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the "audit" entry does not equal "1", is missing, or the line is commented out, this is a finding.

Check that auditing is enabled by default to persist in kernel updates: 

$ sudo grep audit /etc/default/grub

GRUB_CMDLINE_LINUX="audit=1"

If "audit" is not set to "1", is missing or commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to audit processes that start prior to the audit daemon with the following command:

$ sudo grubby --update-kernel=ALL --args="audit=1"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="audit=1"'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52237r779973_chk'
  tag severity: 'medium'
  tag gid: 'V-248803'
  tag rid: 'SV-248803r779975_rule'
  tag stig_id: 'OL08-00-030601'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52191r779974_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
