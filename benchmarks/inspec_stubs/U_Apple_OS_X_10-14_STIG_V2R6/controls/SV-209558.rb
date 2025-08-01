control 'SV-209558' do
  title 'The macOS system must be configured with audit log folders set to mode 700 or less permissive.'
  desc 'The audit service must be configured to create log folders with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.

'
  desc 'check', %q(To check the permissions of the audit log folder, run the following command:

/usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')

The results should show the permissions (first column) to be "700" or less permissive.

if they do not, this is a finding.)
  desc 'fix', 'For any log folder that returns an incorrect permission value, run the following command:

/usr/bin/sudo chmod 700 [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9809r282156_chk'
  tag severity: 'medium'
  tag gid: 'V-209558'
  tag rid: 'SV-209558r610285_rule'
  tag stig_id: 'AOSX-14-001017'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-9809r282157_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag legacy: ['SV-104989', 'V-95851']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
