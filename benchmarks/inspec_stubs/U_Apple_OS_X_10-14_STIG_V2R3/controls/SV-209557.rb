control 'SV-209557' do
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
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9808r282153_chk'
  tag severity: 'medium'
  tag gid: 'V-209557'
  tag rid: 'SV-209557r610285_rule'
  tag stig_id: 'AOSX-14-001016'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-9808r282154_fix'
  tag 'documentable'
  tag legacy: ['V-95849', 'SV-104987']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
