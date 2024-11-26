control 'SV-48372' do
  title 'Permissions for the Security event log must prevent access by non-privileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The Security event log may disclose sensitive information or be  susceptible to tampering if proper permissions are not applied.'
  desc 'check', 'Verify the permissions on the Security event log (Security.evtx).  Standard user accounts or groups must not have access.  The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.  They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.'
  desc 'fix', 'Ensure the permissions on the Security event log (Security.evtx) are configured to prevent standard user accounts or groups from having access.  The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45041r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36723'
  tag rid: 'SV-48372r3_rule'
  tag stig_id: 'WN08-GE-000003-02'
  tag gtitle: 'WINAU-000205'
  tag fix_id: 'F-41503r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
