control 'SV-254183' do
  title 'Nutanix AOS must protect audit information from unauthorized access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify Nutanix AOS audit log permissions are "0600" or less permissive.

$ sudo stat -c "%a %n" /home/log/audit/audit.log
600 /home/log/audit/audit.log

If the audit.log file(s) are more permissive than "0600", this is a finding.'
  desc 'fix', 'Run the salt stack call to set the audit log file permissions to "600".

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57668r846635_chk'
  tag severity: 'medium'
  tag gid: 'V-254183'
  tag rid: 'SV-254183r846637_rule'
  tag stig_id: 'NUTX-OS-000930'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-57619r846636_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
