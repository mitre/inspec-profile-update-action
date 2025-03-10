control 'SV-104175' do
  title 'Symantec ProxySG providing forward proxy intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance.

NIST SP 800-52 sets TLS version 1.1 as a minimum version; therefore, all versions of SSL are not allowed (including for client negotiation) either on DoD-only or public-facing servers.'
  desc 'check', 'Verify that TLS forward proxy intermediary services are configured to comply with NIST 800-52 TLS settings.

1. Log on to the Web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, for each SSL Access Layer that is configured, Verify there is a rule with an action set to "Deny" that also has "Source" and "Destination" fields that contain restricted SSL/TLS protocols and ciphers.

If Symantec ProxySG providing forward proxy intermediary services for TLS is not configured to comply with the required TLS settings in NIST SP 800-52, this is a finding.'
  desc 'fix', 'Configure TLS forward proxy intermediary services to comply with NIST SP 800-52 TLS settings.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, click Policy >> Add SSL Access Layer.
4. Right-click the "Source" field of the existing rule and select "Set". Click "New" and select "Combined Source Object".
5. Click "New" and select "Client Negotiated Cipher". Select all ciphers that should be permitted and click "OK".
6. Click the upper "Add" button and click the "Negate" checkbox.
7. Click "New" and select "Client Negotiated SSL Version". Select all SSL versions that should be permitted and click "OK".
8. Click the upper "Add" button.
9. Click "OK" and then "OK" again.
10. Repeat steps 4 to 9 for the "Destination" field, using the "Server Negotiated Cipher" and "Server Negotiated SSL Version" objects.
11. Right-click the "Action" field of the rule, click "Set", and select "Deny".
12. Click File >> Install Policy on SG Appliance.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93407r1_chk'
  tag severity: 'high'
  tag gid: 'V-94221'
  tag rid: 'SV-104175r1_rule'
  tag stig_id: 'SYMP-AG-000030'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-100337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
