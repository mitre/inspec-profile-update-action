control 'SV-209553' do
  title 'The macOS system must be configured with audit log files owned by root.'
  desc 'The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the ownership of the audit log files, run the following command:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | grep -v current

The results should show the owner (third column) to be "root". 

If they do not, this is a finding.)
  desc 'fix', 'For any log file that returns an incorrect owner, run the following command:

/usr/bin/sudo chown root [audit log file]

[audit log file] is the full path to the log file in question.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9804r282141_chk'
  tag severity: 'medium'
  tag gid: 'V-209553'
  tag rid: 'SV-209553r610285_rule'
  tag stig_id: 'AOSX-14-001012'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-9804r282142_fix'
  tag 'documentable'
  tag legacy: ['SV-104979', 'V-95841']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
