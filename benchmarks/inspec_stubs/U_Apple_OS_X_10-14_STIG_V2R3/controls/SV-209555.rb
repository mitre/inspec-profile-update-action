control 'SV-209555' do
  title 'The macOS system must be configured with audit log files group-owned by wheel.'
  desc 'The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the group ownership of the audit log files, run the following command:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current

The results should show the group owner (fourth column) to be "wheel". 

If they do not, this is a finding.)
  desc 'fix', 'For any log file that returns an incorrect group owner, run the following command:

/usr/bin/sudo chgrp wheel [audit log file]

[audit log file] is the full path to the log file in question.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9806r282147_chk'
  tag severity: 'medium'
  tag gid: 'V-209555'
  tag rid: 'SV-209555r610285_rule'
  tag stig_id: 'AOSX-14-001014'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-9806r282148_fix'
  tag 'documentable'
  tag legacy: ['V-95845', 'SV-104983']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
