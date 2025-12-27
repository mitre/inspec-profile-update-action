control 'SV-100143' do
  title 'The SLES for vRealize must protect audit information from unauthorized read access - ownership.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.'
  desc 'check', 'Verify that the system audit logs are owned by "root":

# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; ls -l ${audit_log_file%/*}; else printf "audit log file(s) not found\\n"; fi)

If any audit log file is not owned by "root", this is a finding.'
  desc 'fix', 'Change the ownership of the audit log file(s).

Procedure:
# chown root <audit log file>

# chown root /var/log/audit/audit.log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89493'
  tag rid: 'SV-100143r1_rule'
  tag stig_id: 'VRAU-SL-000150'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-96235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
