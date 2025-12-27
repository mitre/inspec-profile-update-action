control 'SV-233888' do
  title 'The Infoblox system must present only approved TLS and SSL cipher suites.'
  desc 'Infoblox systems ship with a wide range of cipher suites to support management in a variety of customer environments. Infoblox may have customers that require these cipher suites for backward compatibility. Over time specific cipher suites may become unfavorable for a variety of reasons, including being replaced by stronger suites, or vulnerabilities are discovered and they are no longer considered secure.

Configuration of cipher suites within NIOS directly affects the default HTTPS management system. Note that Infoblox systems do not enable Secure Shell (SSH) by default, but it can be enabled by system administrators and shares configuration of the cipher suites with HTTPS.'
  desc 'check', 'Configuration of the SSL/TLS cipher suite is performed on the Grid Master, or the stand-alone system using the CLI. 

1. Use the following commands to display the status and configuration: 
show ssl_tls_settings
show ssl_tls_protocols
show ssl_tls_ciphers
2. Review the output from "show ssl_tls_ciphers" and note those marked as "enabled".  
3. Compare this to the list of currently approved ciphers.  DISA recommends:

Ciphers:
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_256_CBC_SHA256

Protocols: 
TLSv1.2

If any unapproved cipher suites are enabled, this is a finding.'
  desc 'fix', '1. Close all existing HTTPS management sessions and log on to the Grid Master, or the stand-alone system using the CLI. 
2. Use the following command to display the status: "show ssl_tls_settings".
3. If the output shows "default", the system administrator must first override the default settings to enable editing using the following command: "set ssl_tls_settings override".
4. For each cipher suite to be disabled, use the following procedure. Identify the numerical designation of the cipher suite using: "show ssl_tls_ciphers".
5. Use the following command to disable, replacing NNN with the appropriate number: "set ssl_tls_ciphers disable NNN".
6. Repeat this procedure to disable unapproved cipher suites. The numerical list will be reordered each time it is modified and requires careful validation. 
7. In addition to specific cipher suites, a set of SSL/TLS protocols can also be enabled or disabled as desired. 
8. Review the output from "show ssl_tls_protocols" from the Check procedure.
9. Use the CLI command: "set ssl_tls_protocols disable TLSv1.0", to disable TLS v1.0.
10. Use the CLI command: "set ssl_tls_protocols disable TLSv1.1", to disable TLS v1.1.
11. Use the "show ssl_tls_settings" and show "ssl_tls_protocols" commands to ensure compliance.
12. Using an approved web browser, verify functionality if protocol or TLS settings were modified.

Refer to the Infoblox CLI Guide for additional information if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37073r611184_chk'
  tag severity: 'medium'
  tag gid: 'V-233888'
  tag rid: 'SV-233888r621666_rule'
  tag stig_id: 'IDNS-8X-400030'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37038r611185_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
