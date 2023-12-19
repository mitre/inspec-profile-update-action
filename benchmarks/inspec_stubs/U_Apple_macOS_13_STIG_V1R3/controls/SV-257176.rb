control 'SV-257176' do
  title 'The macOS system must be configured with audit log files set to mode 440 or less permissive.'
  desc 'The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', "Verify the macOS system is configured with audit log files set to mode 440 or less with the following command:

/usr/bin/sudo /bin/ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current

If the files are not mode 440 or less, this is a finding."
  desc 'fix', 'Configure the macOS system with audit log files set to mode 440 with the following command:

/usr/bin/sudo /bin/chmod 440 [audit log file]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60861r905159_chk'
  tag severity: 'medium'
  tag gid: 'V-257176'
  tag rid: 'SV-257176r905161_rule'
  tag stig_id: 'APPL-13-001016'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60802r905160_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
