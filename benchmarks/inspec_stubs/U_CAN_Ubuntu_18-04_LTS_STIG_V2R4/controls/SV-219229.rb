control 'SV-219229' do
  title 'The Ubuntu operating system must permit only authorized accounts ownership of the audit log files.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized modification.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'Verify that the audit log files are owned by "root" account.

First determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, check if the audit log files are owned by the "root" user by using the following command:

# sudo stat -c "%n %U" /var/log/audit/*
/var/log/audit/audit.log root

If the audit log files are owned by an user other than "root", this is a finding.'
  desc 'fix', 'Configure the audit log files to be owned by "root" user.

First determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, configure the audit log files to be owned by "root" user by using the following command:

# sudo chown root /var/log/audit/*'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20954r305015_chk'
  tag severity: 'medium'
  tag gid: 'V-219229'
  tag rid: 'SV-219229r610963_rule'
  tag stig_id: 'UBTU-18-010306'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-20953r305016_fix'
  tag satisfies: ['SRG-OS-000058-GPOS-00028', 'SRG-OS-000057-GPOS-00027']
  tag 'documentable'
  tag legacy: ['SV-109789', 'V-100685']
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
