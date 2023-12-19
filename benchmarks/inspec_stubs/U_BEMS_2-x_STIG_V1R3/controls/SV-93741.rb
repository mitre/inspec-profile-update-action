control 'SV-93741' do
  title 'If the Mail service (Push Notifications support for BlackBerry Work) is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to Enable SSL LDAP for certificate directory lookup.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS) or SSL.'
  desc 'check', 'This requirement is not applicable if the Mail service (Push Notifications support for BlackBerry Work) is not enabled on BEMS.

Verify Enable SSL LDAP for LDAP Lookup for certificates for the Mail service is configured in BEMS as follows:

1. In the BEMS Dashboard, under BlackBerry Services Configuration, click mail and then click Certificate Directory Lookup
2. If the Enable LDAP Lookup has been selected, verify the Enable SSL LDAP check box is also selected.

When LDAP Lookup for certificates has been configured on BEMS, if Enable SSL LDAP is not configured, this is a finding.'
  desc 'fix', 'Enable SSL LDAP when using LDAP Lookup for certificates for the Mail service in BEMS as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
2. Click "Certificate Directory Lookup".
3. Select the "Enable LDAP Lookup" check box.
4. Select the "Enable SSL LDAP" check box.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79035'
  tag rid: 'SV-93741r1_rule'
  tag stig_id: 'BEMS-00-014100'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
