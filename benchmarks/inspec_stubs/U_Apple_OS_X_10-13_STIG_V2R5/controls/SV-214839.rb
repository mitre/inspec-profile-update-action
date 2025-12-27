control 'SV-214839' do
  title 'The macOS system must be configured with audit log files owned by root.'
  desc 'The audit service must be configured to create log files with the correct ownership to prevent regular users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the ownership of the audit log files, run the following command:

/usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | grep -v current

The results should show the owner (third column) to be "root". 

If they do not, this is a finding.)
  desc 'fix', 'For any log file that returns an incorrect owner, run the following command:

/usr/bin/sudo chown root [audit log file]

[audit log file] is the full path to the log file in question.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16039r397089_chk'
  tag severity: 'medium'
  tag gid: 'V-214839'
  tag rid: 'SV-214839r609363_rule'
  tag stig_id: 'AOSX-13-000331'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-16037r397090_fix'
  tag 'documentable'
  tag legacy: ['SV-96253', 'V-81539']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
