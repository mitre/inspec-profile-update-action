control 'SV-234965' do
  title 'The SUSE operating system must allocate audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.'
  desc 'To ensure SUSE operating systems have a sufficient storage capacity in which to write the audit logs, SUSE operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the SUSE operating system.'
  desc 'check', 'Verify the SUSE operating system allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

Determine to which partition the audit records are being written with the following command:

> sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the example being /var/log/audit/) with the following command:

> df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var

If the audit records are not written to a partition made specifically for audit records (/var/log/audit is a separate partition), determine the amount of space being used by other files in the partition with the following command:

> sudo du -sh [audit_partition]
1.8G /var/log/audit

The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. In normal circumstances, 10.0 GB of storage space for audit records will be sufficient.

If the audit record partition is not allocated sufficient storage capacity, this is a finding.'
  desc 'fix', 'Allocate enough storage capacity for at least one week of SUSE operating system audit records when audit records are not immediately sent to a central audit record storage facility.

If audit records are stored on a partition made specifically for audit records, use the "YaST2 - Partitioner" program (installation and configuration tool for Linux) to resize the partition with sufficient space to contain one week of audit records.

If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient amount of space will need be to be created. The new partition can be created using the "YaST2 - Partitioner" program on the system.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38153r619164_chk'
  tag severity: 'medium'
  tag gid: 'V-234965'
  tag rid: 'SV-234965r622137_rule'
  tag stig_id: 'SLES-15-030660'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-38116r619165_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
