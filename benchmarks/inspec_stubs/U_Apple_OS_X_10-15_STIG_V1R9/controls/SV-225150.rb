control 'SV-225150' do
  title 'The macOS system must be configured with audit log files set to mode 440 or less permissive.'
  desc 'The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the permissions of the audit log files, run the following command:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current

The results should show the permissions (first column) to be "440" or less permissive.

If they do not, this is a finding.)
  desc 'fix', 'For any log file that returns an incorrect permission value, run the following command:

/usr/bin/sudo chmod 440 [audit log file]

[audit log file] is the full path to the log file in question.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26849r467618_chk'
  tag severity: 'medium'
  tag gid: 'V-225150'
  tag rid: 'SV-225150r610901_rule'
  tag stig_id: 'AOSX-15-001016'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-26837r467619_fix'
  tag 'documentable'
  tag legacy: ['V-102863', 'SV-111825']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
