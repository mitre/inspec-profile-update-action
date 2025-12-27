control 'SV-104257' do
  title 'Symantec ProxySG providing forward proxy encryption intermediary services must use NIST FIPS-validated cryptography to implement encryption services.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the Federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'Verify that TLS intermediary services are configured to comply with NIST FIPS-validated cryptography.

1. Log on to the Web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, for each SSL Access Layer that is configured, verify there is a rule with an action set to "Deny" that also has "Source" and "Destination" fields that contain a negated list of NIST FIPS-validated SSL/TLS protocols and ciphers.

If Symantec ProxySG providing forward proxy encryption intermediary services does not use NIST FIPS-validated cryptography to implement encryption services, this is a finding.'
  desc 'fix', 'Configure TLS intermediary services to comply with NIST FIPS-validated cryptography.

1. Log on to the Web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, click Policy >> Add SSL Access Layer.
4. Right-click the "Source" field of the existing rule and select "Set". Click "New" and select "Combined Source Object".
5. Click "New" and select "Client Negotiated Cipher". Select all ciphers that should be permitted and click "OK".
6. Click the upper "Add" button and click the "Negate" checkbox.
7. Click "New" and select "Client Negotiated SSL Version". Select all NIST FIPS-validated SSL versions that should be permitted and click "OK".
8. Click the upper "Add" button.
9. Click "OK" and then "OK" again.
10. Repeat steps 4-9 for the "Destination" field using the "Server Negotiated Cipher" and "Server Negotiated SSL Version" objects.
11. Right-click the "Action" field of the rule, click "Set", and select "Deny".
12. Click File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93489r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94303'
  tag rid: 'SV-104257r1_rule'
  tag stig_id: 'SYMP-AG-000450'
  tag gtitle: 'SRG-NET-000510-ALG-000111'
  tag fix_id: 'F-100419r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
