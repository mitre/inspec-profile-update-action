control 'SV-252466' do
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
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55922r816210_chk'
  tag severity: 'medium'
  tag gid: 'V-252466'
  tag rid: 'SV-252466r816212_rule'
  tag stig_id: 'APPL-12-001012'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-55872r816211_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
