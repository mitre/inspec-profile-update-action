control 'SV-248831' do
  title 'OL 8 must not have the stream control transmission protocol (SCTP) kernel module installed if not required for operational support.'
  desc 'The SCTP is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the "sctp" kernel module.  
 
$ sudo grep -r sctp /etc/modprobe.d/* | grep -i "/bin/false" | grep -v "^#" 
 
install sctp /bin/true 
 
If the command does not return any output or the line is commented out, and use of SCTP is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.  
 
Verify the operating system disables the ability to use SCTP with the following command:  
 
$ sudo grep sctp /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#" 
 
blacklist sctp 
 
If the command does not return any output or the output is not "blacklist sctp", and use of SCTP is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to use the "sctp" kernel module. 
 
Create a file under "/etc/modprobe.d" with the following command: 
 
$ sudo touch /etc/modprobe.d/sctp.conf 
 
Add the following line to the created file: 
 
install sctp /bin/true 
 
Configure OL 8 to disable the ability to use the sctp kernel module. 
 
$ sudo vi /etc/modprobe.d/blacklist.conf 
 
Add or update the line: 
 
blacklist sctp'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52265r780057_chk'
  tag severity: 'medium'
  tag gid: 'V-248831'
  tag rid: 'SV-248831r780059_rule'
  tag stig_id: 'OL08-00-040023'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52219r780058_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
