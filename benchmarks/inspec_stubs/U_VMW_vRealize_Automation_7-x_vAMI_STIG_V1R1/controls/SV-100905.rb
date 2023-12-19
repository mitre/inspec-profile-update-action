control 'SV-100905' do
  title 'The vAMI must use approved versions of TLS.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).Transmission of data can take place between the application server and a large number of devices/applications external to the application server. Examples are a web client used by a user, a backend database, a log server, or other application servers in an application server cluster. If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.'
  desc 'check', 'At the command prompt, execute the following command:

grep ssl.use-sslv /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "ssl.use-sslv2" and "ssl.use-sslv3" are not "disable", this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the lighttpd.conf file with the following two values: 
'ssl.use-sslv2 = "disable"'
'ssl.use-sslv3 = "disable"'

Note: Both values must be present.)
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90255'
  tag rid: 'SV-100905r1_rule'
  tag stig_id: 'VRAU-VA-000565'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag fix_id: 'F-96997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
