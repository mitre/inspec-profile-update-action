control 'SV-257173' do
  title 'The macOS system must be configured with audit log folders owned by root.'
  desc 'The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', "Verify the macOS system is configured with audit log folders owned by root with the following command:

/usr/bin/sudo /bin/ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')

If the folders are not owned by root, this is a finding."
  desc 'fix', 'Configure the macOS system with audit log folders owned by root with the following command:

/usr/bin/sudo chown root [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60858r905150_chk'
  tag severity: 'medium'
  tag gid: 'V-257173'
  tag rid: 'SV-257173r905152_rule'
  tag stig_id: 'APPL-13-001013'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60799r905151_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
