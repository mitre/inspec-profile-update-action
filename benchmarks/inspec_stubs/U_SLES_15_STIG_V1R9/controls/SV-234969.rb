control 'SV-234969' do
  title 'The SUSE operating system auditd service must notify the System Administrator (SA) and Information System Security Officer (ISSO) immediately when audit storage capacity is 75 percent full.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Determine if the SUSE operating system auditd is configured to notify the SA and ISSO when the audit record storage volume reaches 75 percent of the storage capacity.

Check the system configuration to determine the partition to which audit records are written using the following command:

> sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition to which audit records are written (e.g., "/var/log/audit/"):

> df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var

If the audit records are not being written to a partition specifically created for audit records (in this example "/var/log/audit" is a separate partition), use the following command to determine the amount of space other files in the partition currently occupy:

> sudo du -sh <partition>
1.8G /var/log/audit

Determine the threshold for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:

> sudo grep -iw space_left /etc/audit/auditd.conf
space_left = 225 

If the value of the "space_left" keyword is not set to 25 percent of the total partition size, this is a finding.'
  desc 'fix', 'Check the system configuration to determine the partition to which the audit records are written: 

> sudo grep -iw log_file /etc/audit/auditd.conf

Determine the size of the partition to which audit records are written (e.g., "/var/log/audit/"):

> df -h /var/log/audit/

Set the value of the "space_left" keyword in "/etc/audit/auditd.conf" to 25 percent of the partition size.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38157r619176_chk'
  tag severity: 'medium'
  tag gid: 'V-234969'
  tag rid: 'SV-234969r877389_rule'
  tag stig_id: 'SLES-15-030700'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-38120r619177_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
