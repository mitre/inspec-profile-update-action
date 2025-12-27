control 'SV-99967' do
  title 'Lighttpd must use an approved TLS version for encryption.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.

SSL/TLS is a collection of protocols. Weaknesses have been identified with earlier SSL protocols, including SSLv2 and SSLv3, hence SSL versions 1, 2, and 3 should no longer be used. The best practice for transport layer protection is to only provide support for the TLS protocols - TLS 1.0, TLS 1.1 and TLS 1.2. This configuration will provide maximum protection against skilled and determined attackers and is appropriate for applications handling sensitive data or performing critical operations.

Lighttpd must explicitly disable all of the SSL-series protocols. If these protocols are not disabled, the vRA appliance may be vulnerable to a loss of confidentiality.'
  desc 'check', %q(At the command prompt, execute the following command:

Note:  The command should return 2 outputs: ssl.use-sslv2 and ssl.use-sslv3

grep '^ssl.use-sslv' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value returned for "ssl.use-sslv2" and "ssl.use-sslv3" are not set to "disable", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf file with following:

ssl.use-sslv2 = "disable"

ssl.use-sslv3 = "disable"'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-89009r1_chk'
  tag severity: 'high'
  tag gid: 'V-89317'
  tag rid: 'SV-99967r1_rule'
  tag stig_id: 'VRAU-LI-000485'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-96059r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
