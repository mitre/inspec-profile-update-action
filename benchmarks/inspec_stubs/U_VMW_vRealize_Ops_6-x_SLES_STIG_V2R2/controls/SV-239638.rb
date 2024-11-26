control 'SV-239638' do
  title 'Audit logs must be rotated daily.'
  desc 'Rotate audit logs daily to preserve audit file system space and to conform to the DISA requirement. If it is not rotated daily and moved to another location, then there is more of a chance for the compromise of audit data by malicious users.'
  desc 'check', 'Check for a logrotate entry that rotates audit logs.

# ls -l /etc/logrotate.d/audit

If it exists, check for the presence of the daily rotate flag:

# egrep "daily" /etc/logrotate.d/audit

The command should produce a "daily" entry in the logrotate file for the audit daemon. 

If the daily entry is missing, this is a finding.'
  desc 'fix', 'Create or edit the "/etc/logrotate.d/audit" file and add the daily entry, such as:

/var/log/audit/audit.log {
compress
dateext
rotate 15
daily
missingok
notifempty
create 600 root root
sharedscripts
postrotate
/sbin/service auditd restart 2> /dev/null > /dev/null || true
endscript
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42871r662363_chk'
  tag severity: 'medium'
  tag gid: 'V-239638'
  tag rid: 'SV-239638r662365_rule'
  tag stig_id: 'VROM-SL-001445'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-42830r662364_fix'
  tag 'documentable'
  tag legacy: ['SV-99397', 'V-88747']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
