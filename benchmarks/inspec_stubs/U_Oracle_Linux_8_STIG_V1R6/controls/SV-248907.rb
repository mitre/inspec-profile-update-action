control 'SV-248907' do
  title 'OL 8 must prevent non-privileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 
 
Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Verify the operating system prevents non-privileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. 
 
Obtain a list of authorized users (other than System Administrator and guest accounts) for the system. 
 
Check the list against the system by using the following command: 
 
$ sudo semanage login -l | more 
Login Name SELinux User MLS/MCS Range Service 
__default__ user_u s0-s0:c0.c1023 * 
root unconfined_u s0-s0:c0.c1023 * 
system_u system_u s0-s0:c0.c1023 * 
joe staff_u s0-s0:c0.c1023 * 
 
All administrators must be mapped to the "sysadm_u", "staff_u", or an appropriately tailored confined role as defined by the organization. 
 
All authorized non-administrative users must be mapped to the "user_u" role. 
 
If they are not mapped in this way, this is a finding.'
  desc 'fix', 'Configure OL 8 to prevent non-privileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. 
 
Use the following command to map a new user to the "sysadm_u" role: 
 
$ sudo semanage login -a -s sysadm_u <username> 
 
Use the following command to map an existing user to the "sysadm_u" role: 
 
$ sudo semanage login -m -s sysadm_u <username> 
 
Use the following command to map a new user to the "staff_u" role: 
 
$ sudo semanage login -a -s staff_u <username> 
 
Use the following command to map an existing user to the "staff_u" role: 
 
$ sudo semanage login -m -s staff_u <username> 
 
Use the following command to map a new user to the "user_u" role: 
 
$ sudo  semanage login -a -s user_u <username> 
 
Use the following command to map an existing user to the "user_u" role: 
 
$ sudo semanage login -m -s user_u <username>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52341r780285_chk'
  tag severity: 'medium'
  tag gid: 'V-248907'
  tag rid: 'SV-248907r877392_rule'
  tag stig_id: 'OL08-00-040400'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-52295r780286_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
