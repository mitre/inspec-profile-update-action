control 'SV-214845' do
  title 'The macOS system must be configured so that log files must not contain access control lists (ACLs).'
  desc 'The audit service must be configured to create log files with the correct permissions to prevent regular users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check if a log file contains ACLs, run the following commands:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current

In the output from the above commands, ACLs will be listed under any file that may contain them (e.g., "0: group:admin allow list,readattr,reaadextattr,readsecurity").

If any such line exists, this is a finding.)
  desc 'fix', 'For any log file that contains ACLs, run the following command:

/usr/bin/sudo chmod -N [audit log file]'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16045r397107_chk'
  tag severity: 'medium'
  tag gid: 'V-214845'
  tag rid: 'SV-214845r609363_rule'
  tag stig_id: 'AOSX-13-000337'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-16043r397108_fix'
  tag 'documentable'
  tag legacy: ['SV-96265', 'V-81551']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
