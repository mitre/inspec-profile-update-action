control 'SV-209554' do
  title 'The macOS system must be configured with audit log folders owned by root.'
  desc 'The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.'
  desc 'check', %q(To check the ownership of the audit log folder, run the following command:

/usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')

The results should show the owner (third column) to be "root". 

If it does not, this is a finding.)
  desc 'fix', 'For any log folder that has an incorrect owner, run the following command:

/usr/bin/sudo chown root [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9805r282144_chk'
  tag severity: 'medium'
  tag gid: 'V-209554'
  tag rid: 'SV-209554r610285_rule'
  tag stig_id: 'AOSX-14-001013'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-9805r282145_fix'
  tag 'documentable'
  tag legacy: ['SV-104981', 'V-95843']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
