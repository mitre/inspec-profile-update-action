control 'SV-248829' do
  title 'OL 8 must not have the asynchronous transfer mode (ATM) kernel module installed if not required for operational support.'
  desc 'The ATM is a transport layer protocol 
designed for digital transmission of multiple types of traffic, including telephony (voice), data, and video signals, in one network without the use of separate overlay networks. Disabling ATM protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the "atm" kernel module.  
 
$ sudo grep -r atm /etc/modprobe.d/* | grep -i "/bin/false" | grep -v "^#" 
 
install atm /bin/true 
 
If the command does not return any output or the line is commented out, and use of ATM is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.  
 
Verify the operating system disables the ability to use ATM with the following command:  
 
$ sudo grep atm /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#" 
 
blacklist atm 
 
If the command does not return any output or the output is not "blacklist atm", and use of ATM is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to use the "atm" kernel module. 
 
Create a file under "/etc/modprobe.d" with the following command: 
 
$ sudo touch /etc/modprobe.d/atm.conf 
 
Add the following line to the created file: 
 
install atm /bin/true 
 
Configure OL 8 to disable the ability to use the atm kernel module. 
 
$ sudo vi /etc/modprobe.d/blacklist.conf 
 
Add or update the line: 
 
blacklist atm'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52263r780051_chk'
  tag severity: 'medium'
  tag gid: 'V-248829'
  tag rid: 'SV-248829r780053_rule'
  tag stig_id: 'OL08-00-040021'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52217r780052_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
