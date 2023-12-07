control 'SV-48373' do
  title 'Permissions for the System event log must prevent access by non-privileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The System event log may be  susceptible to tampering if proper permissions are not applied.'
  desc 'check', 'Verify the permissions on the System event log (System.evtx). Standard user accounts or groups must not have access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory. They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.'
  desc 'fix', 'Ensure the permissions on the System event log (System.evtx) are configured to prevent standard user accounts or groups from having access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36724'
  tag rid: 'SV-48373r3_rule'
  tag stig_id: 'WN08-GE-000003-03'
  tag gtitle: 'WINAU-000206'
  tag fix_id: 'F-42653r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
