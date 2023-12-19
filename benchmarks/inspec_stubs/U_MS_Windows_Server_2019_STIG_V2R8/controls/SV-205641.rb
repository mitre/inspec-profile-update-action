control 'SV-205641' do
  title 'Windows Server 2019 permissions for the Security event log must prevent access by non-privileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Security event log may disclose sensitive information or be susceptible to tampering if proper permissions are not applied.

'
  desc 'check', 'Navigate to the Security event log file.

The default location is the "%SystemRoot%\\System32\\winevt\\Logs" folder. However, the logs may have been moved to another folder.

If the permissions for the "Security.evtx" file are not as restrictive as the default permissions listed below, this is a finding:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control'
  desc 'fix', 'Configure the permissions on the Security event log file (Security.evtx) to prevent access by non-privileged accounts. The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\System32\\winevt\\Logs" folder.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5906r354841_chk'
  tag severity: 'medium'
  tag gid: 'V-205641'
  tag rid: 'SV-205641r569188_rule'
  tag stig_id: 'WN19-AU-000040'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-5906r354842_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag legacy: ['V-93191', 'SV-103279']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
