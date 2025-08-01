control 'SV-254721' do
  title 'If the Mail service (Push Notifications support for BlackBerry Work) is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to Enable SSL LDAP when using LDAP Lookup for users.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS) or SSL.'
  desc 'check', 'This requirement is not applicable if the Mail service (Push Notifications support for BlackBerry Work) is not enabled on BEMS.

Verify Enable SSL LDAP for LDAP Lookup for users for the Mail service is configured in BEMS as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
2. Click "User Directory Lookup".
3. If the "Enable LDAP Lookup" has been selected, verify the "Enable SSL LDAP" check box is also selected.

When LDAP Lookup for user has been configured on BEMS, if Enable SSL LDAP is not configured, this is a finding.'
  desc 'fix', 'Enable SSL LDAP when using LDAP Lookup for users for the Mail service in BEMS as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
2. Click "User Directory Lookup".
3. Select the "Enable LDAP Lookup" check box.
4. Select the "Enable SSL LDAP" check box.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58332r861886_chk'
  tag severity: 'medium'
  tag gid: 'V-254721'
  tag rid: 'SV-254721r879887_rule'
  tag stig_id: 'BEMS-03-014000'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58278r861887_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
