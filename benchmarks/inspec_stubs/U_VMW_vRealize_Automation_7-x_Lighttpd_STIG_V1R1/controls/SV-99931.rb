control 'SV-99931' do
  title 'Lighttpd must be configured to use only FIPS 140-2 approved ciphers.'
  desc 'Use of cryptography to provide confidentiality and non-repudiation is not effective unless strong methods are employed with its use. Many earlier encryption methods and modules have been broken and/or overtaken by increasing computing power. The NIST FIPS 140-2 cryptographic standards provide proven methods and strengths to employ cryptography effectively.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'ssl.cipher-list' /opt/vmware/etc/lighttpd/lighttpd.conf

If the return value for "ssl.cipher-list" is not set to "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Configure the lighttpd.conf file with the following:

ssl.cipher-list = "FIPS: +3DES:!aNULL"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89281'
  tag rid: 'SV-99931r1_rule'
  tag stig_id: 'VRAU-LI-000245'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag fix_id: 'F-96023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
