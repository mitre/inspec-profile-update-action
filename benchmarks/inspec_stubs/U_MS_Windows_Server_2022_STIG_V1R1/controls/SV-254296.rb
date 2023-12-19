control 'SV-254296' do
  title 'Windows Server 2022 permissions for the Application event log must prevent access by nonprivileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Application event log may be susceptible to tampering if proper permissions are not applied.

'
  desc 'check', 'Navigate to the Application event log file.

The default location is the "%SystemRoot%\\System32\\winevt\\Logs" folder. However, the logs may have been moved to another folder.

If the permissions for the "Application.evtx" file are not as restrictive as the default permissions listed below, this is a finding:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control'
  desc 'fix', 'Configure the permissions on the Application event log file (Application.evtx) to prevent access by nonprivileged accounts. The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\System32\\winevt\\Logs" folder.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57781r848702_chk'
  tag severity: 'medium'
  tag gid: 'V-254296'
  tag rid: 'SV-254296r848704_rule'
  tag stig_id: 'WN22-AU-000030'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-57732r848703_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
