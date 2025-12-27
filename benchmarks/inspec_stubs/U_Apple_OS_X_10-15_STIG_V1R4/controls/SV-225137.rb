control 'SV-225137' do
  title 'The macOS system must be configured so that log files must not contain access control lists (ACLs).'
  desc 'The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.

'
  desc 'check', %q(To check if a log file contains ACLs, run the following commands:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current

In the output from the above commands, ACLs will be listed under any file that may contain them (e.g., "0: group:admin allow list,readattr,reaadextattr,readsecurity").

If any such line exists, this is a finding.)
  desc 'fix', 'For any log file that contains ACLs, run the following command:

/usr/bin/sudo chmod -N [audit log file]'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26836r467579_chk'
  tag severity: 'medium'
  tag gid: 'V-225137'
  tag rid: 'SV-225137r610901_rule'
  tag stig_id: 'AOSX-15-000030'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-26824r467580_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag legacy: ['SV-111651', 'V-102689']
  tag cci: ['CCI-001314', 'CCI-000162']
  tag nist: ['SI-11 b', 'AU-9 a']
end
