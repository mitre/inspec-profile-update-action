control 'SV-221899' do
  title 'The Oracle Linux operating system must protect audit information from unauthorized read, modification, or deletion.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized modification.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'Verify the operating system audit records have proper permissions and ownership.

List the full permissions and ownership of the audit log files with the following command.

# ls -la /var/log/audit 
total 4512
drwx------. 2 root root 23 Apr 25 16:53 .
drwxr-xr-x. 17 root root 4096 Aug 9 13:09 ..
-rw-------. 1 root root 8675309 Aug 9 12:54 audit.log

Audit logs must be mode 0600 or less permissive. 
If any are more permissive, this is a finding.

The owner and group owner of all audit log files must both be "root". If any other owner or group owner is listed, this is a finding.'
  desc 'fix', 'Change the mode of the audit log files with the following command: 

# chmod 0600 [audit_file]

Change the owner and group owner of the audit log files with the following command: 

# chown root:root [audit_file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23614r419769_chk'
  tag severity: 'medium'
  tag gid: 'V-221899'
  tag rid: 'SV-221899r603260_rule'
  tag stig_id: 'OL07-00-910055'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-23603r419770_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag legacy: ['V-99537', 'SV-108641']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']
end
