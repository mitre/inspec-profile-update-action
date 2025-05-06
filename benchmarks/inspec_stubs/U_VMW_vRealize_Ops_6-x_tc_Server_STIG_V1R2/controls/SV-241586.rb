control 'SV-241586' do
  title 'tc Server CaSa must be configured with FIPS 140-2 compliant ciphers for HTTPS connections.'
  desc "Encryption of data-in-flight is an essential element of protecting information confidentiality. If a web server uses weak or outdated encryption algorithms, then the server's communications can potentially be compromised.

The US Federal Information Processing Standards (FIPS) publication 140-2, Security Requirements for Cryptographic Modules (FIPS 140-2) identifies eleven areas for a cryptographic module used inside a security system that protects information. FIPS 140-2- approved ciphers provide the maximum level of encryption possible for a private web server.

Configuration of ciphers used by tc Server are set in the “catalina.properties” file. Only those ciphers specified in the configuration file, and which are available in the installed OpenSSL library, will be used by tc Server while encrypting data for transmission."
  desc 'check', "At the command prompt, execute the following command:

grep -A 10 vmware-casa.ssl.ciphers.list /usr/lib/vmware-casa/casa-webapp/conf/catalina.properties

If the value of “vmware-casa.ssl.ciphers.list” does not match the list of FIPS 140-2 ciphers or is missing, this is a finding.

Note: To view a list of FIPS 140-2 ciphers, at the command prompt execute the following command:

openssl ciphers 'FIPS'"
  desc 'fix', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/catalina.properties.

Navigate to and locate “vmware-casa.ssl.ciphers.list”.

Configure the “vmware-casa.ssl.ciphers.list” with FIPS 140-2 compliant ciphers.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44862r684097_chk'
  tag severity: 'medium'
  tag gid: 'V-241586'
  tag rid: 'SV-241586r879519_rule'
  tag stig_id: 'VROM-TC-000070'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-44821r683619_fix'
  tag 'documentable'
  tag legacy: ['SV-99451', 'V-88801']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
