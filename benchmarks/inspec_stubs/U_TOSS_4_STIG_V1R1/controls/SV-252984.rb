control 'SV-252984' do
  title 'The TOSS audit system must protect logon UIDs from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit TOSS system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. A system reboot would be noticeable and a system administrator could then investigate the unauthorized changes.

'
  desc 'check', 'Verify the audit system prevents unauthorized changes to logon UIDs with the following command:

$ sudo grep -i immutable /etc/audit/audit.rules

--loginuid-immutable

If the login UIDs are not set to be immutable by adding the "--loginuid-immutable" option to the "/etc/audit/audit.rules", this is a finding.'
  desc 'fix', 'Configure the audit system to set the logon UIDs to be immutable by adding the following line to "/etc/audit/rules.d/audit.rules":

--loginuid-immutable'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56437r824274_chk'
  tag severity: 'medium'
  tag gid: 'V-252984'
  tag rid: 'SV-252984r824276_rule'
  tag stig_id: 'TOSS-04-030190'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56387r824275_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
