control 'SV-257158' do
  title 'The macOS system must be configured so that log files do not contain access control lists (ACLs).'
  desc 'The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.

'
  desc 'check', %q(Verify the macOS system is configured without ACLs applied to log files with the following command:

/usr/bin/sudo /bin/ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current

In the output from the above command, ACLs will be listed under any file that may contain them (e.g., "0: group:admin allow list,readattr,readextattr,readsecurity").

If any ACLs exists, this is a finding.)
  desc 'fix', 'Configure the macOS system so that log files do not contain ACLs with the following command:

/usr/bin/sudo /bin/chmod -N [audit log file]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60843r905105_chk'
  tag severity: 'medium'
  tag gid: 'V-257158'
  tag rid: 'SV-257158r905107_rule'
  tag stig_id: 'APPL-13-000030'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60784r905106_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-001314']
  tag nist: ['AU-9 a', 'SI-11 b']
end
