control 'SV-29201' do
  title 'Permissions for event logs must conform to minimum requirements.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Event logs may be susceptible to tampering if proper permissions are not applied.'
  desc 'check', 'Verify the permissions on the event logs.  Standard user accounts or groups must not have access.  The default permissions listed below satisfy this requirement.

Navigate to the log file location.  The default location is the "%SystemRoot%\\System32\\winevt\\Logs" directory.
For each log file below, right click the file and select "Properties".
Select the "Security" tab.
Select the "Advanced" button.

Log Files:
Application.evtx
Security.evtx
System.evtx

Permissions:
Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

If the permissions for the file are not as restrictive as those listed, this is a finding.

If the organization has an "Auditors" group from previous requirements, the assignment of Full Control permissions to this group would not be a finding.'
  desc 'fix', 'Maintain the permissions on the event logs.  Standard user accounts or groups must not have access.  The default permissions listed below satisfy this requirement.

Navigate to the log file location.  The default location is the "%SystemRoot%\\System32\\winevt\\Logs" directory.
For each log file below, right click the file and select "Properties".
Select the "Security" tab.
Select the "Advanced" button.

Log Files:
Application.evtx
Security.evtx
System.evtx

Permissions:
Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

If the organization has an "Auditors" group from previous requirements, this group may be assigned Full Control.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-62245r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1077'
  tag rid: 'SV-29201r2_rule'
  tag gtitle: 'Incorrect ACLs for event logs'
  tag fix_id: 'F-67161r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
