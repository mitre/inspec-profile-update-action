control 'SV-104231' do
  title 'Symantec ProxySG providing user authentication intermediary services must require users to reauthenticate every 900 seconds when organization-defined circumstances or situations require reauthentication.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances: 

1. When authenticators change
2. When roles change
3. When security categories of information systems change
4. When the execution of privileged functions occurs
5. After a fixed period of time
6. Periodically

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Reauthentication of users may be enforced by using credential cache lifetimes and inactivity timeouts. Verify credential cache lifetimes and inactivity timeouts for LDAP, RADIUS, XML, IWA (with Basic credentials), SiteMinder, and COREid authentication methods.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Click each of the above authentication mechanisms and select the "General" tab (e.g., Radius General or LDAP General).
4. Verify that the "Credential Refresh" time is set to the organization-defined time period.

If Symantec ProxySG providing user authentication intermediary services does not require users to reauthenticate every 900 seconds when organization-defined circumstances or situations require reauthentication, this is a finding.'
  desc 'fix', 'Reauthentication of users may be enforced by using credential cache lifetimes and inactivity timeouts. Set credential cache lifetimes and inactivity timeouts for LDAP, RADIUS, XML, IWA (with Basic credentials), SiteMinder, and COREid authentication methods.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Click each of the above authentication mechanisms and select the "General" tab (e.g., Radius General or LDAP General).
4. Set the "Credential Refresh" time to the organization-defined time period.
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93463r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94277'
  tag rid: 'SV-104231r1_rule'
  tag stig_id: 'SYMP-AG-000310'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-100393r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
