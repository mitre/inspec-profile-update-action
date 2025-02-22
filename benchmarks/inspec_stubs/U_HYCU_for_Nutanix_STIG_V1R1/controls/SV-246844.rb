control 'SV-246844' do
  title 'The HYCU server must protect audit tools from unauthorized access, modification, and deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify the operating system audit tools and config files have proper permissions and ownership.

Log on to the HYCU console and list the full permissions and ownership of the audit folder with the following command:
sudo ls  -al /etc/audit

Folder and files must be owned by root and the following permissions must be set: 
drwxr-x---.   4 root root  126 Mar 15 10:16 .
drwxr-xr-x. 106 root root 8192 May  6 13:58 ..
-rw-r-----.   1 root root  751 Apr 24  2020 audisp-remote.conf
-rw-r-----.   1 root root  856 Apr 24  2020 auditd.conf
-rw-r-----.   1 root root  107 Feb  3 13:18 audit.rules
-rw-r-----.   1 root root  127 Apr 24  2020 audit-stop.rules
drwxr-x---.   2 root root   67 Mar 15 10:16 plugins.d
drwxr-x---.   2 root root   25 Feb  3 13:13 rules.d

Audit files must be mode 0640 or less permissive. If any are more permissive, this is a finding.

The owner and group owner of all audit files must both be "root". If any other owner or group owner is listed, this is a finding.'
  desc 'fix', 'Change the mode of the audit log files with the following command:
# chmod 0640 [audit_file]

Change the owner and group owner of the audit files with the following command:
# chown root:root [audit_file]'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50276r768194_chk'
  tag severity: 'medium'
  tag gid: 'V-246844'
  tag rid: 'SV-246844r768196_rule'
  tag stig_id: 'HYCU-AU-000021'
  tag gtitle: 'SRG-APP-000121-NDM-000238'
  tag fix_id: 'F-50230r768195_fix'
  tag satisfies: ['SRG-APP-000121-NDM-000238', 'SRG-APP-000122-NDM-000239', 'SRG-APP-000123-NDM-000240']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
