control 'SV-240926' do
  title 'The vAMI must use FIPS 140-2 approved ciphers when transmitting management data during remote access management sessions.'
  desc 'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. Types of management interfaces utilized by an application server include web-based HTTPS interfaces as well as command line-based management interfaces.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^ssl.cipher-list' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "ssl.cipher-list" is not set to "FIPS: +3DES:!aNULL", or is missing or is commented out, this is a finding.)
  desc 'fix', %q(Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the lighttpd.conf file with the following value: 'ssl.cipher-list = "FIPS: +3DES:!aNULL"')
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44159r675943_chk'
  tag severity: 'high'
  tag gid: 'V-240926'
  tag rid: 'SV-240926r879519_rule'
  tag stig_id: 'VRAU-VA-000010'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-44118r675944_fix'
  tag 'documentable'
  tag legacy: ['SV-100845', 'V-90195']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
