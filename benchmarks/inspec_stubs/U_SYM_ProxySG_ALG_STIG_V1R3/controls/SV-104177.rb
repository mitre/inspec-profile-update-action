control 'SV-104177' do
  title 'Symantec ProxySG providing reverse proxy intermediary services for TLS must be configured to version 1.1 or higher with an approved cipher suite.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance.'
  desc 'check', 'Verify that TLS reverse proxy intermediary services are configured to comply with NIST 800-52 TLS settings.

1. Verify with the ProxySG administrator that reverse proxy services are configured. 
2. Log on to the Web Management Console. 
3. Click Configuration >> Services >> Proxy Services. 
4. For each reverse proxy service identified by the administrator, click "Edit Service" and Verify that only NIST SP 800-52-approved SSL protocols are enabled.
5. Log on to the ProxySG SSH CLI.
6. Type "enable" and enter the enable password.
7. Type "configure" and press "Enter".
8. Type "proxy-services" and press "Enter".
9. For each reverse proxy service identified by the administrator, type "edit <reverse proxy service name".
10. Type "view" and verify that only NIST SP 800-52-compliant cipher suites are listed.

If Symantec ProxySG providing reverse proxy intermediary services for TLS is not configured to version 1.1 or higher with an approved cipher suite, this is a finding.'
  desc 'fix', 'Verify that TLS reverse proxy intermediary services are configured to comply with NIST SP 800-52 TLS settings.

1. Verify with the ProxySG administrator that reverse proxy services are configured. 
2. Log on to the Web Management Console. 
3. Click Configuration >> Services >> Proxy Services. 
4. For each reverse proxy service configured, click "Edit Service" and select only NIST-SP 800-52-approved SSL protocols. Click "Apply".
5. Log on to the ProxySG SSH CLI.
6. Type "enable" and enter the enable password.
7. Type "configure" and press "Enter".
8. Type "proxy-services" and press "Enter".
9. For each reverse proxy service identified by the administrator, type "edit <reverse proxy service name".
10. Type "attribute" followed by a list of the desired NIST SP 800-52-compliant cipher suites.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94223'
  tag rid: 'SV-104177r1_rule'
  tag stig_id: 'SYMP-AG-000040'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-100339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
