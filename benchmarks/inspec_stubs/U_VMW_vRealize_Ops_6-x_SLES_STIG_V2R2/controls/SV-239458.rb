control 'SV-239458' do
  title 'The SLES for vRealize must protect audit information from unauthorized modification.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the SLES for vRealize must protect audit information from unauthorized modification.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Check that the SLES for vRealize audit logs with the following command:

# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; ls -l ${audit_log_file%/*}; else printf "audit log file(s) not found\\n"; fi)

If any audit log file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the mode of the audit log file(s):

# chmod 0640 <audit log file>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42691r661823_chk'
  tag severity: 'medium'
  tag gid: 'V-239458'
  tag rid: 'SV-239458r661825_rule'
  tag stig_id: 'VROM-SL-000160'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-42650r661824_fix'
  tag 'documentable'
  tag legacy: ['SV-99037', 'V-88387']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
