control 'SV-239716' do
  title 'VAMI must be configured with FIPS 140-2 compliant ciphers for HTTPS connections.'
  desc "Encryption of data in flight is an essential element of protecting information confidentiality. If a web server uses weak or outdated encryption algorithms, the server's communications can potentially be compromised.

The US Federal Information Processing Standards (FIPS) publication 140-2, Security Requirements for Cryptographic Modules (FIPS 140-2), identifies 11 areas for a cryptographic module used inside a security system that protects information. FIPS 140-2 approved ciphers provide the maximum level of encryption possible for a private web server.

VAMI is compiled to use VMware's FIPS-validated OpenSSL module and cannot be configured otherwise. Ciphers may still be specified in order of preference, but no non-FIPS-approved ciphers will be implemented.

"
  desc 'check', 'At the command prompt, execute the following command:

# /opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf|grep "ssl.cipher-list"

Expected result:

ssl.cipher-list                   = "!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES"

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/applmgmt/appliance/lighttpd.conf.

Add or reconfigure the following value:

ssl.cipher-list                   = "!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES"'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.7 VAMI-lighttpd'
  tag check_id: 'C-42949r679256_chk'
  tag severity: 'high'
  tag gid: 'V-239716'
  tag rid: 'SV-239716r679258_rule'
  tag stig_id: 'VCLD-67-000002'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-42908r679257_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000416-WSR-000118', 'SRG-APP-000439-WSR-000188']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'IA-7', 'SC-8']
end
