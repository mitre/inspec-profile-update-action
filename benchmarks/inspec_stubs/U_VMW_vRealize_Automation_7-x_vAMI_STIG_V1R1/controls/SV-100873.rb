control 'SV-100873' do
  title 'The vAMI must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Application servers have the capability to utilize either certificates (tokens) or user IDs and passwords in order to authenticate. When the application server transmits or receives passwords, the passwords must be encrypted.'
  desc 'check', %q(At the command prompt, execute the following command:
 
grep '^ssl.engine' /opt/vmware/etc/lighttpd/lighttpd.conf
 
If the value of "ssl.engine" is not set to "enable", or is missing or is commented out, this is a finding.)
  desc 'fix', %q(Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the lighttpd.conf file with the following value: 'ssl.engine = "enable"')
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89915r1_chk'
  tag severity: 'high'
  tag gid: 'V-90223'
  tag rid: 'SV-100873r1_rule'
  tag stig_id: 'VRAU-VA-000235'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-96965r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
