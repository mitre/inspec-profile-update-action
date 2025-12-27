control 'SV-253341' do
  title 'Windows 11 permissions for the Security event log must prevent access by non-privileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. The Security event log may disclose sensitive information or be susceptible to tampering if proper permissions are not applied.'
  desc 'check', 'Verify the permissions on the Security event log (Security.evtx). Standard user accounts or groups must not have access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory. They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.

Note: If "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES" has Special Permissions, this would not be a finding.'
  desc 'fix', 'Ensure the permissions on the Security event log (Security.evtx) are configured to prevent standard user accounts or groups from having access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56794r829105_chk'
  tag severity: 'medium'
  tag gid: 'V-253341'
  tag rid: 'SV-253341r829107_rule'
  tag stig_id: 'WN11-AU-000520'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56744r829106_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
