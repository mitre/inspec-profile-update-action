control 'SV-219230' do
  title 'The Ubuntu operating system must permit only authorized groups to own the audit log files.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized modification.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'Verify that the audit log files are owned by "root" group.

First determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, check if the audit log files are owned by the "root" group by using the following command:

# sudo stat -c "%n %G" /var/log/audit/*
/var/log/audit/audit.log root

If the audit log files are owned by a group other than "root", this is a finding.'
  desc 'fix', 'Configure the audit log files to be owned by "root" group.

First determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, configure the audit log files to be owned by "root" group by using the following command:

# sudo chown :root /var/log/audit/*'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20955r305018_chk'
  tag severity: 'medium'
  tag gid: 'V-219230'
  tag rid: 'SV-219230r610963_rule'
  tag stig_id: 'UBTU-18-010307'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-20954r305019_fix'
  tag satisfies: ['SRG-OS-000058-GPOS-00028', 'SRG-OS-000057-GPOS-00027']
  tag 'documentable'
  tag legacy: ['SV-109791', 'V-100687']
  tag cci: ['CCI-000163', 'CCI-000162']
  tag nist: ['AU-9 a', 'AU-9 a']
end
