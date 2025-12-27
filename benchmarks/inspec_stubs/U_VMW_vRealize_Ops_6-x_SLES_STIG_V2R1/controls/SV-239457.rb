control 'SV-239457' do
  title 'The SLES for vRealize must protect audit information from unauthorized read access - group ownership.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit SLES for vRealize activity.'
  desc 'check', 'Verify that the SLES for vRealize audit logs are group-owned by "root".

# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; ls -l ${audit_log_file%/*}; else printf "audit log file(s) not found\\n"; fi)

If any audit log file is not group-owned by "root" or "admin", this is a finding.'
  desc 'fix', 'Change the group ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>

# chgrp root /var/log/audit/audit.log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42690r661820_chk'
  tag severity: 'medium'
  tag gid: 'V-239457'
  tag rid: 'SV-239457r661822_rule'
  tag stig_id: 'VROM-SL-000155'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-42649r661821_fix'
  tag 'documentable'
  tag legacy: ['SV-99035', 'V-88385']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
