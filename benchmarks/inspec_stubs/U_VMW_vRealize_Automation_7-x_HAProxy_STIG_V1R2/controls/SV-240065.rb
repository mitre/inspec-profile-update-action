control 'SV-240065' do
  title 'HAProxy must be configured to use only FIPS 140-2 approved ciphers.'
  desc 'Use of cryptography to provide confidentiality and non-repudiation is not effective unless strong methods are employed with its use. Many earlier encryption methods and modules have been broken and/or overtaken by increasing computing power. The NIST FIPS 140-2 cryptographic standards provide proven methods and strengths to employ cryptography effectively.'
  desc 'check', %q(At the command prompt, execute the following command:

grep -E 'bind.*ssl' /etc/haproxy/conf.d/30-vro-config.cfg /etc/haproxy/conf.d/20-vcac.cfg

If the return value for SSL cipher list is not set to "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', "Navigate to and open the following files:

/etc/haproxy/conf.d/30-vro-config.cfg 
/etc/haproxy/conf.d/20-vcac.cfg

Navigate to the frontend section in each file.

Configure the bind keyword file with this cipher list: 

'FIPS: +3DES:!aNULL'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43298r665362_chk'
  tag severity: 'medium'
  tag gid: 'V-240065'
  tag rid: 'SV-240065r879616_rule'
  tag stig_id: 'VRAU-HA-000210'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag fix_id: 'F-43257r665363_fix'
  tag 'documentable'
  tag legacy: ['SV-99817', 'V-89167']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
