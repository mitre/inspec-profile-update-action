control 'WDNS-22-000006_rule' do
  title 'The "Manage auditing and security log" user right must be assigned only to authorized personnel.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. The actual auditing is performed by the operating system/network device manager, but the configuration to trigger the auditing is controlled by the DNS server.

Because the configuration of the audit logs on the DNS server dictates which events are logged to correlate events, the permissions for configuring the audit logs must be restricted to only those with the role of information system security manager (ISSM) or those appointed by the ISSM.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Manage auditing and security log" user right, this is a finding:

Administrators 
Auditors (if the site has an Auditors group that further limits this privilege)

If an application requires this user right, this is not a finding. Vendor documentation must support the requirement for having the user right. The requirement must be documented with the ISSO. The application account must meet requirements for application account passwords.

Verify the permissions on the DNS logs.

Standard user accounts or groups must not have greater than READ access.

The default locations are:

DNS Server %SystemRoot%\\System32\\Winevt\\Logs\\DNS Server.evtx

Using the file explorer tool, navigate to the DNS server log file.

Right-click on the log file and select the "Security" tab.

The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

If the permissions for these files are not as restrictive as the access control lists above, this is a finding.'
  desc 'fix', 'Configure the permissions on the DNS logs.

Standard user accounts or groups must not have greater than READ access.

The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default locations are:

DNS Server %SystemRoot%\\System32\\Winevt\\Logs\\DNS Server.evtx'
  impact 0.5
  tag check_id: 'C-WDNS-22-000006_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000006'
  tag rid: 'WDNS-22-000006_rule'
  tag stig_id: 'WDNS-22-000006'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-WDNS-22-000006_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
