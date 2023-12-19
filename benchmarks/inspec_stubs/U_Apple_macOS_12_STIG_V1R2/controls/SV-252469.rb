control 'SV-252469' do
  title 'The macOS system must be configured with audit log folders group-owned by wheel.'
  desc 'The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the group ownership of the audit log folder, run the following command:

/usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')

The results should show the group (fourth column) to be "wheel".

If they do not, this is a finding.)
  desc 'fix', 'For any log folder that has an incorrect group, run the following command:

/usr/bin/sudo chgrp wheel [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55925r816219_chk'
  tag severity: 'medium'
  tag gid: 'V-252469'
  tag rid: 'SV-252469r816221_rule'
  tag stig_id: 'APPL-12-001015'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-55875r816220_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
