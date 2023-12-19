control 'SV-252978' do
  title 'TOSS audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify the audit log directory has a mode of "0700" or less permissive.

First, determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the directory where the audit log file is located, check if the audit log directory has a mode of "0700" or less permissive with the following command:

$ sudo ls -ld /var/log/audit/
drwx------. 2 root root 99 Jul 19 07:32 /var/log/audit/

If the audit log directory has a mode more permissive than "0700", this is a finding.'
  desc 'fix', 'Configure the audit log directory to be protected from unauthorized read access by setting the correct permissive mode with the following command:

$ sudo chmod 0700 [audit_log_directory]

Replace "[audit_log_directory]" to the correct audit log directory path, by default this location is "/var/log/audit."'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56431r824256_chk'
  tag severity: 'medium'
  tag gid: 'V-252978'
  tag rid: 'SV-252978r824258_rule'
  tag stig_id: 'TOSS-04-030130'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56381r824257_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
