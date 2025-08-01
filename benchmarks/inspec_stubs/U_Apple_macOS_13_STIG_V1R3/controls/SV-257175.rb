control 'SV-257175' do
  title 'The macOS system must be configured with audit log folders group-owned by wheel.'
  desc 'The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', "Verify the macOS system is configured with audit log folders group-owned by wheel with the following command:

/usr/bin/sudo /bin/ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')

If the folders are not group-owned by wheel, this is a finding."
  desc 'fix', 'Configure the macOS system with audit log folders group-owned by wheel with the following command:

/usr/bin/sudo chgrp wheel [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60860r905156_chk'
  tag severity: 'medium'
  tag gid: 'V-257175'
  tag rid: 'SV-257175r905158_rule'
  tag stig_id: 'APPL-13-001015'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60801r905157_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
