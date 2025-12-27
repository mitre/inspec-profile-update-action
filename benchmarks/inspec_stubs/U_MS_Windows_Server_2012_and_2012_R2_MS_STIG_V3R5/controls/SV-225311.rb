control 'SV-225311' do
  title 'Permissions for the Security event log must prevent access by nonprivileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The Security event log may disclose sensitive information or be  susceptible to tampering if proper permissions are not applied.'
  desc 'check', 'Verify the permissions on the Security event log (Security.evtx).  Standard user accounts or groups must not have access.  The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.  They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.'
  desc 'fix', 'Ensure the permissions on the Security event log (Security.evtx) are configured to prevent standard user accounts or groups from having access.  The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27010r471275_chk'
  tag severity: 'medium'
  tag gid: 'V-225311'
  tag rid: 'SV-225311r569185_rule'
  tag stig_id: 'WN12-AU-000205'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-26998r471276_fix'
  tag 'documentable'
  tag legacy: ['SV-51571', 'V-36723']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
