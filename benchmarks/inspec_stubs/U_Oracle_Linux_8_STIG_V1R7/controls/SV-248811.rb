control 'SV-248811' do
  title 'OL 8 must allocate audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.'
  desc 'To ensure OL 8 systems have a sufficient storage capacity in which to write the audit logs, OL 8 needs to be able to allocate audit record storage capacity. 
 
The task of allocating audit record storage capacity is usually performed during initial installation of OL 8.'
  desc 'check', 'Verify OL 8 allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility. 
 
Determine to which partition the audit records are being written with the following command: 
 
$ sudo grep -iw log_file /etc/audit/auditd.conf 
log_file = /var/log/audit/audit.log 
 
Check the size of the partition to which audit records are written (with the example being "/var/log/audit/") with the following command: 
 
$ sudo df -h /var/log/audit/ 
/dev/sda2 24G 10.4G 13.6G 43% /var/log/audit 
 
If the audit records are not written to a partition made specifically for audit records ("/var/log/audit" is a separate partition), determine the amount of space being used by other files in the partition with the following command: 
 
$ sudo du -sh [audit_partition] 
1.8G /var/log/audit 
 
If the audit record partition is not allocated for sufficient storage capacity, this is a finding. 
 
Note: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. Typically 10.0 GB of storage space for audit records should be sufficient.'
  desc 'fix', 'Allocate enough storage capacity for at least one week of audit records when audit records are not immediately sent to a central audit record storage facility. 
 
If audit records are stored on a partition made specifically for audit records, use the "X" program to resize the partition with sufficient space to contain one week of audit records. 
 
If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient space will need be to be created.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52245r818685_chk'
  tag severity: 'medium'
  tag gid: 'V-248811'
  tag rid: 'SV-248811r877391_rule'
  tag stig_id: 'OL08-00-030660'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-52199r779998_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
