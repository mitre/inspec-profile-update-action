control 'SV-257177' do
  title 'The macOS system must be configured with audit log folders set to mode 700 or less permissive.'
  desc 'The audit service must be configured to create log folders with the correct permissions to prevent normal users from reading audit logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by root or administrative users with sudo, the risk is mitigated.

'
  desc 'check', "Verify the macOS system is configured with audit log folders set to mode 700 or less with the following command:

/usr/bin/sudo /bin/ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')

If the folders are not set to mode 700 or less, this is a finding."
  desc 'fix', 'Configure the macOS system with audit log folders set to mode 700 with the following command:

/usr/bin/sudo /bin/chmod 700 [audit log folder]'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60862r905162_chk'
  tag severity: 'medium'
  tag gid: 'V-257177'
  tag rid: 'SV-257177r905164_rule'
  tag stig_id: 'APPL-13-001017'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-60803r905163_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
