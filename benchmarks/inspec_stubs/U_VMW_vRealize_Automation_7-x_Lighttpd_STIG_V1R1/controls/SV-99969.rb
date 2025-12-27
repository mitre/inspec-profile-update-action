control 'SV-99969' do
  title 'Lighttpd must remove all export ciphers to transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference. The Lighttpd will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^ssl.cipher-list' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value returned in not "ssl.cipher-list = "FIPS: +3DES:!aNULL" "or is commented out, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf file with the following: 

ssl.cipher-list = "FIPS: +3DES:!aNULL"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-89011r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89319'
  tag rid: 'SV-99969r1_rule'
  tag stig_id: 'VRAU-LI-000490'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-96061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
