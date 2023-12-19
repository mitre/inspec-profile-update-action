control 'SV-225149' do
  title 'The macOS system must be configured with audit log folders group-owned by wheel.'
  desc 'The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the group ownership of the audit log folder, run the following command:

/usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')

The results should show the group (fourth column) to be "wheel".

If they do not, this is a finding.)
  desc 'fix', 'For any log folder that has an incorrect group, run the following command:

/usr/bin/sudo chgrp wheel [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26848r467615_chk'
  tag severity: 'medium'
  tag gid: 'V-225149'
  tag rid: 'SV-225149r610901_rule'
  tag stig_id: 'AOSX-15-001015'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-26836r467616_fix'
  tag 'documentable'
  tag legacy: ['V-102715', 'SV-111677']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
