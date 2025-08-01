control 'SV-81489' do
  title 'The Tanium Application Server must be configured to only use Microsoft Active Directory for account management functions.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the cog of the Windows Operating System and separate maintenance will not be required.'
  desc 'check', %q(Access the Tanium App server through interactive logon.

Run regedit as Administrator.

Navigate to HKLM\Software\Wow6432Node\Tanium\Tanium Server.

Validate the "cac_ldap_server_url" value exists and is configured to point to the site's Active Directory instance. 

This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that is logging in. 

It must use the syntax of LDAP://<AD instance FQDN> (Note: All CAPS for LDAP).

If the value for  "cac_ldap_server_url" does not exist or is not configured to the site's AD instance, this is a finding.)
  desc 'fix', %q(Access the Tanium App server through interactive logon.

Run regedit as Administrator.

Navigate to HKLM\Software\Wow6432Node\Tanium\Tanium Server. 

Set the value for "cac_ldap_server_url" to reference the site's AD instance.

It must use the syntax of LDAP://<AD instance FQDN> (Note: All CAPS for LDAP).)
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66999'
  tag rid: 'SV-81489r1_rule'
  tag stig_id: 'TANS-CN-000003'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-73099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
