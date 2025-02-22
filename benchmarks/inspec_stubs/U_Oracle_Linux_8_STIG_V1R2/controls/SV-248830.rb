control 'SV-248830' do
  title 'OL 8 must not have the Controller Area Network (CAN) kernel module installed if not required for operational support.'
  desc "The CAN protocol is a robust vehicle bus standard designed to allow microcontrollers and devices to communicate with each other's applications without a host computer. Disabling CAN protects the system against exploitation of any flaws in its implementation."
  desc 'check', 'Verify the operating system disables the ability to load the "can" kernel module.  
 
$ sudo grep -r can /etc/modprobe.d/* | grep -i "/bin/false" | grep -v "^#" 
 
install can /bin/true 
 
If the command does not return any output or the line is commented out, and use of "can" is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.  
 
Verify the operating system disables the ability to use CAN with the following command:  
 
$ sudo grep can /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#" 
 
blacklist can 
 
If the command does not return any output or the output is not "blacklist can", and use of CAN is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to use the "can" kernel module. 
 
Create a file under "/etc/modprobe.d" with the following command: 
 
$ sudo touch /etc/modprobe.d/can.conf 
 
Add the following line to the created file: 
 
install can /bin/true 
 
Configure OL 8 to disable the ability to use the can kernel module. 
 
$ sudo vi /etc/modprobe.d/blacklist.conf 
 
Add or update the line: 
 
blacklist can'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52264r780054_chk'
  tag severity: 'medium'
  tag gid: 'V-248830'
  tag rid: 'SV-248830r780056_rule'
  tag stig_id: 'OL08-00-040022'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52218r780055_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
