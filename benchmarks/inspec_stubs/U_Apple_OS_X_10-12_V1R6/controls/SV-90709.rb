control 'SV-90709' do
  title 'The OS X system must be configured with audit log folders owned by root.'
  desc 'The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the ownership of the audit log folder, run the following command:

/usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')

The results should show the owner (third column) to be "root". 

If it does not, this is a finding.)
  desc 'fix', 'For any log folder that has an incorrect owner, run the following command:

/usr/bin/sudo chown root [audit log folder]'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75705r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76021'
  tag rid: 'SV-90709r1_rule'
  tag stig_id: 'AOSX-12-000332'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-82659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
