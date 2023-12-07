control 'SV-215652' do
  title 'The Windows 2012 DNS Server logging criteria must only be configured by the ISSM or individuals appointed by the ISSM.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.

Since the configuration of the audit logs on the DNS server dictates which events are logged for the purposes of correlating events, the permissions for configuring the audit logs must be restricted to only those with the role of ISSM or those appointed by the ISSM.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Manage auditing and security log" user right, this is a finding:

Administrators 
Auditors (if the site has an Auditors group that further limits this privilege.)

If an application requires this user right, this would not be a finding. 
Vendor documentation must support the requirement for having the user right. 
The requirement must be documented with the ISSO. 
The application account must meet requirements for application account passwords.

Verify the permissions on the DNS logs.

Standard user accounts or groups must not have greater than READ access.

The default locations are:

DNS Server %SystemRoot%\\System32\\Winevt\\Logs\\DNS Server.evtx

Using the file explorer tool navigate to the DNS Server log file.

Right click on the log file, select the “Security” tab.

The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.'
  desc 'fix', 'Configure the permissions on the DNS logs.

Standard user accounts or groups must not have greater than READ access.

The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default locations are:

DNS Server %SystemRoot%\\System32\\Winevt\\Logs\\DNS Server.evtx'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16846r314431_chk'
  tag severity: 'medium'
  tag gid: 'V-215652'
  tag rid: 'SV-215652r561297_rule'
  tag stig_id: 'WDNS-AU-000007'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-16844r314432_fix'
  tag 'documentable'
  tag legacy: ['SV-72983', 'V-58553']
  tag cci: ['CCI-000171', 'CCI-000366']
  tag nist: ['AU-12 b', 'CM-6 b']
end
