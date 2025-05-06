control 'SV-246843' do
  title 'The HYCU server must protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit data.'
  desc 'check', 'Verify the operating system audit records have proper permissions and ownership.

Log on to the HYCU console and list the full permissions and ownership of the audit log files with the following command:
# sudo ls -la /var/log/audit
total 4512
drwx------. 2 root root 23 Apr 25 16:53 .
drwxr-xr-x. 17 root root 4096 Aug 9 13:09 ..
-rw-------. 1 root root 8675309 Aug 9 12:54 audit.log

Audit logs must be mode 0600 or less permissive. If any are more permissive, this is a finding.

The owner and group owner of all audit log files must both be "root". If any other owner or group owner is listed, this is a finding.'
  desc 'fix', 'Change the mode of the audit log files with the following command:
# chmod 0600 [audit_file]

Change the owner and group owner of the audit log files with the following command:
# chown root:root [audit_file]'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50275r768191_chk'
  tag severity: 'medium'
  tag gid: 'V-246843'
  tag rid: 'SV-246843r768193_rule'
  tag stig_id: 'HYCU-AU-000020'
  tag gtitle: 'SRG-APP-000120-NDM-000237'
  tag fix_id: 'F-50229r768192_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
