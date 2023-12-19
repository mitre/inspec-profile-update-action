control 'SV-257174' do
  title 'The macOS system must be configured with audit log files group-owned by wheel.'
  desc 'The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', "Verify the macOS system is configured with audit log files group-owned by wheel with the following command:

/usr/bin/sudo /bin/ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current

If the files are not group-owned by wheel, this is a finding."
  desc 'fix', 'Configure the macOS system with audit log files group-owned by wheel with the following command:

/usr/bin/sudo chgrp wheel [audit log file]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60859r905153_chk'
  tag severity: 'medium'
  tag gid: 'V-257174'
  tag rid: 'SV-257174r905155_rule'
  tag stig_id: 'APPL-13-001014'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60800r905154_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
