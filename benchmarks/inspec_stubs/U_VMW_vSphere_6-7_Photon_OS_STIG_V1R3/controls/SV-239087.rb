control 'SV-239087' do
  title 'The Photon operating system audit log must have correct permissions.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.'
  desc 'check', 'At the command line, execute the following command:

# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; stat -c "%n permissions are %a" ${audit_log_file%}*; else printf "audit log file(s) not found\\n"; fi)

If the permissions on any audit log file is more permissive than 0600, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

#  chmod 0600 <audit log file>

Replace <audit log file> with the log files more permissive than 0600.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42298r675067_chk'
  tag severity: 'medium'
  tag gid: 'V-239087'
  tag rid: 'SV-239087r675069_rule'
  tag stig_id: 'PHTN-67-000015'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-42257r675068_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
