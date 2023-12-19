control 'SV-215245' do
  title 'Audit logs on the AIX system must be set to 660 or less permissive.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Check the log files under the audit logging directory have correct permissions.

The default log file is /audit/trail.

The log file can be set by the "trail" variable in /etc/security/audit/config.
# grep trail /etc/security/audit/config
        trail = /audit/trail

# ls -l <auditlog dir>
total 240
-rw-rw----    1 root     system            0 Feb 23 08:44 bin1
-rw-rw----    1 root     system            0 Feb 23 08:44 bin2
-rw-r-----    1 root     system       116273 Feb 23 08:44 trail

If any file has a mode more permissive than "660", this is a finding.'
  desc 'fix', 'Set the permission of the audit log file to "660".

# chmod 660 <auditlog file>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16443r294186_chk'
  tag severity: 'medium'
  tag gid: 'V-215245'
  tag rid: 'SV-215245r508663_rule'
  tag stig_id: 'AIX7-00-002015'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-16441r294187_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag legacy: ['V-91267', 'SV-101367']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
