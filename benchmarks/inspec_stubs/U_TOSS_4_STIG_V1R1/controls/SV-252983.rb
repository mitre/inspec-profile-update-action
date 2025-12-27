control 'SV-252983' do
  title 'The TOSS audit system must protect auditing rules from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit TOSS system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. A system reboot would be noticeable and a system administrator could then investigate the unauthorized changes.

'
  desc 'check', 'Verify the audit system prevents unauthorized changes with the following command:

$ sudo grep "^\\s*[^#]" /etc/audit/audit.rules | tail -1

-e 2

If the audit system is not set to be immutable by adding the "-e 2" option to the "/etc/audit/audit.rules", this is a finding.'
  desc 'fix', 'Configure the audit system to set the audit rules to be immutable by adding the following line to the end of "/etc/audit/rules.d/audit.rules":

-e 2

Note: Once set, the system must be rebooted for auditing to be changed. It is recommended to add this option as the last step in securing the system.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56436r824271_chk'
  tag severity: 'medium'
  tag gid: 'V-252983'
  tag rid: 'SV-252983r824273_rule'
  tag stig_id: 'TOSS-04-030180'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56386r824272_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
