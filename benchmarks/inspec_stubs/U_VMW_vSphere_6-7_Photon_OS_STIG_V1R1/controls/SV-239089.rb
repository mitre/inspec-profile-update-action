control 'SV-239089' do
  title 'The Photon operating system audit log must be group-owned by root.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.'
  desc 'check', 'At the command line, execute the following command:

# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; stat -c "%n is group owned by %G" ${audit_log_file%}*; else printf "audit log file(s) not found\\n"; fi)

If any audit log file is not group-owned by root, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

#  chown root:root <audit log file>

Replace <audit log file> with the log files not group owned by root.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42300r675073_chk'
  tag severity: 'medium'
  tag gid: 'V-239089'
  tag rid: 'SV-239089r675075_rule'
  tag stig_id: 'PHTN-67-000017'
  tag gtitle: 'SRG-OS-000059-GPOS-00029'
  tag fix_id: 'F-42259r675074_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
