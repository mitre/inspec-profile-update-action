control 'SV-248738' do
  title 'The OL 8 audit system must protect auditing rules from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit OL 8 system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. A system reboot would be noticeable and a system administrator could then investigate the unauthorized changes.

'
  desc 'check', 'Verify the audit system prevents unauthorized changes with the following command:

$ sudo grep "^\\s*[^#]" /etc/audit/audit.rules | tail -1

-e 2

If the audit system is not set to be immutable by adding the "-e 2" option to the "/etc/audit/audit.rules", this is a finding.'
  desc 'fix', 'Configure the audit system to set the audit rules to be immutable by adding the following line to "/etc/audit/rules.d/audit.rules":

-e 2

Note: Once set, the system must be rebooted for auditing to be changed. It is recommended to add this option as the last step in securing the system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52172r779778_chk'
  tag severity: 'medium'
  tag gid: 'V-248738'
  tag rid: 'SV-248738r779780_rule'
  tag stig_id: 'OL08-00-030121'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-52126r779779_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
