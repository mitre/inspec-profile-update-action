control 'SV-104247' do
  title 'Symantec ProxySG must prohibit the use of cached authenticators after 300 seconds at a minimum.'
  desc 'If the cached authenticator information is out of date, the validity of the authentication information may be questionable.

This requirement applies to all ALGs that may cache user authenticators for use throughout a session. It also applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Verify credential cache lifetimes for LDAP, RADIUS, XML, IWA (with Basic credentials), SiteMinder, and COREid authentication methods.

1. Log on to the Web Management Console.
2. Browse to Configuration, >> Authentication.
3. Click each of the above authentication mechanisms and select the "General" tab (e.g., Radius General or LDAP General).
4. Verify that the "Credential Refresh" time is set to the organization-defined time period (a minimum of 300 seconds).

If Symantec ProxySG does not prohibit the use of cached authenticators after 300 seconds at a minimum, this is a finding.'
  desc 'fix', 'Set credential cache lifetimes for LDAP, RADIUS, XML, IWA (with Basic credentials), SiteMinder, and COREid authentication methods.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Click each of the above authentication mechanisms and select the "General" tab (e.g., Radius General or LDAP General).
4. Set the "Credential Refresh" time to 300 at a minimum.
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93479r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94293'
  tag rid: 'SV-104247r1_rule'
  tag stig_id: 'SYMP-AG-000390'
  tag gtitle: 'SRG-NET-000344-ALG-000098'
  tag fix_id: 'F-100409r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
