control 'SV-243490' do
  title 'Usage of administrative accounts must be monitored for suspicious and anomalous activity.'
  desc 'Monitoring the usage of administrative accounts can alert on suspicious behavior and anomalous account usage that would be indicative of potential malicious credential reuse.'
  desc 'check', 'Verify account usage events for administrative accounts are being monitored.  This includes events related to approved administrative accounts as well as accounts being added to privileged groups such as Administrators, Domain and Enterprise Admins and other organization defined administrative groups.  Event monitoring may be implemented through various methods including log aggregation and the use of monitoring tools.

Monitor for the events listed below, at minimum.  If these events are not monitored, this is a finding.

Account Lockouts (Subcategory: User Account Management)
4740 - A user account is locked out.
User Added to Privileged Group (Subcategory: Security Group Management)
4728 - A member was added to a security-enabled global group.
4732 - A member was added to a security-enabled local group.
4756 - A member was added to a security-enabled universal group.
Successful User Account Login (Subcategory: Logon)
4624 - An account was successfully logged on.
Failed User Account Login (Subcategory: Logon)
4625 - An account failed to log on.
Account Login with Explicit Credentials (Subcategory: Logon)
4648 - A logon was attempted using explicit credentials.'
  desc 'fix', %q(Monitor account usage events for administrative accounts.  This includes events related to approved administrative accounts as well as accounts being added to privileged groups such as Administrators, Domain and Enterprise Admins and other organization defined administrative groups.  Event monitoring may be implemented through various methods including log aggregation and the use of monitoring tools.

Monitor for the events listed below, at minimum.

Account Lockouts (Subcategory: User Account Management)
4740 - A user account is locked out.
User Added to Privileged Group (Subcategory: Security Group Management)
4728 - A member was added to a security-enabled global group.
4732 - A member was added to a security-enabled local group.
4756 - A member was added to a security-enabled universal group.
Successful User Account Login (Subcategory: Logon)
4624 - An account was successfully logged on.
Failed User Account Login (Subcategory: Logon)
4625 - An account failed to log on.
Account Login with Explicit Credentials (Subcategory: Logon)
4648 - A logon was attempted using explicit credentials.

The "Account Usage" section of NSA's "Spotting the Adversary with Windows Event Log Monitoring" provides additional information.
https://www.iad.gov/iad/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm.)
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46765r723503_chk'
  tag severity: 'medium'
  tag gid: 'V-243490'
  tag rid: 'SV-243490r723505_rule'
  tag stig_id: 'AD.AU.0001'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46722r723504_fix'
  tag 'documentable'
  tag legacy: ['V-43712', 'SV-56533']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
