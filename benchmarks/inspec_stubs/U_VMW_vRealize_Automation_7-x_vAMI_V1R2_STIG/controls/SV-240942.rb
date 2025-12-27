control 'SV-240942' do
  title 'The vAMI must use approved versions of TLS.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. The use of TLS provides confidentiality of data in transit between the application server and client. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.'
  desc 'check', 'At the command prompt, execute the following command:

grep ssl.use-sslv /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "ssl.use-sslv2" and "ssl.use-sslv3" are not "disable", this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the lighttpd.conf file with the following two values: 
'ssl.use-sslv2 = "disable"'
'ssl.use-sslv3 = "disable"'

Note: Both values must be present.)
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44175r675991_chk'
  tag severity: 'high'
  tag gid: 'V-240942'
  tag rid: 'SV-240942r879616_rule'
  tag stig_id: 'VRAU-VA-000265'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-44134r675992_fix'
  tag 'documentable'
  tag legacy: ['SV-100877', 'V-90227']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
