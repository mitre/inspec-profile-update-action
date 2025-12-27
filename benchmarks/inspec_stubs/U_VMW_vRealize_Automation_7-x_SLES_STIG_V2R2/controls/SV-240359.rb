control 'SV-240359' do
  title 'The SLES for vRealize must protect audit information from unauthorized read access - group-ownership.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.'
  desc 'check', 'Verify that the system audit logs are group-owned by "root":

# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; ls -l ${audit_log_file%/*}; else printf "audit log file(s) not found\\n"; fi)

If any audit log file is not group-owned by "root" or "admin", this is a finding.'
  desc 'fix', 'Change the group-ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>

# chgrp root /var/log/audit/audit.log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43592r670816_chk'
  tag severity: 'medium'
  tag gid: 'V-240359'
  tag rid: 'SV-240359r670818_rule'
  tag stig_id: 'VRAU-SL-000155'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-43551r670817_fix'
  tag 'documentable'
  tag legacy: ['SV-100145', 'V-89495']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
