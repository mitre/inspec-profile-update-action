control 'SV-104261' do
  title 'Symantec ProxySG providing reverse proxy encryption intermediary services must implement NIST FIPS-validated cryptography for digital signatures.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the Federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'Verify that TLS reverse proxy intermediary services are configured to comply with NIST FIPS-validated cryptography.

1. Verify with the ProxySG administrator that reverse proxy services are configured. 
2. Log on to the Web Management Console.
3. Click Configuration >> Services >> Proxy Services. 
4. For each reverse proxy service identified by the administrator, click "Edit Service" and Verify that only NIST FIPS-validated SSL protocols are enabled.
5. Log on to the ProxySG SSH CLI.
6. Type "enable" and enter the enable password.
7. Type "configure" and press "Enter".
8. Type "proxy-services" and press "Enter".
9. For each reverse proxy service identified by the administrator, type "edit <reverse proxy service name".
10. Type "view" and verify that only NIST FIPS-validated cipher suites are listed.

For more information, see the Blue Coat Reverse Proxy WebGuide.

If Symantec ProxySG providing reverse proxy encryption intermediary services does not implement NIST FIPS-validated cryptography for digital signatures, this is a finding.'
  desc 'fix', 'Configure TLS reverse proxy intermediary services to comply with NIST FIPS-validated cryptography.

1. Verify with the ProxySG administrator that reverse proxy services are configured. 
2. Log on to the Web Management Console.
3. Click Configuration >> Services >> Proxy Services. 
4. For each reverse proxy service configured, click "Edit Service" and select only NIST FIPS-validated SSL protocols. Click "Apply".
5. Log on to the ProxySG SSH CLI.
6. Type "enable" and enter the enable password.
7. Type "configure" and press "Enter".
8. Type "proxy-services" and press "Enter".
9. For each reverse proxy service identified by the administrator, type "edit <reverse proxy service name".
10. Type "attribute" followed by a list of the desired NIST FIPS-validated cipher suites.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93493r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94307'
  tag rid: 'SV-104261r1_rule'
  tag stig_id: 'SYMP-AG-000470'
  tag gtitle: 'SRG-NET-000510-ALG-000040'
  tag fix_id: 'F-100423r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
