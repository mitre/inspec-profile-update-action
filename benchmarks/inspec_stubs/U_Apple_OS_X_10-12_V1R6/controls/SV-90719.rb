control 'SV-90719' do
  title 'The OS X system must be configured so that log files must not contain access control lists (ACLs).'
  desc 'The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check if a log file contains ACLs, run the following commands:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current

In the output from the above commands, ACLs will be listed under any file that may contain them (e.g., "0: group:admin allow list,readattr,reaadextattr,readsecurity").

If any such line exists, this is a finding.)
  desc 'fix', 'For any log file that contains ACLs, run the following command:

/usr/bin/sudo chmod -N [audit log file]'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75715r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76031'
  tag rid: 'SV-90719r1_rule'
  tag stig_id: 'AOSX-12-000337'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-82669r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
