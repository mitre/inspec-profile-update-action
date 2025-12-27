control 'SV-245563' do
  title 'The AIX /etc/syslog.conf file must have a mode of 0640 or less permissive.'
  desc 'Unauthorized permissions of the /etc/syslog.conf file can lead to the ability for a malicious actor to alter or disrupt system logging activities. This can aid the malicious actor in avoiding detection and further their ability to conduct malicious activities on the system.'
  desc 'check', 'Check the mode of /etc/syslog.conf using command:
# ls -al /etc/syslog.conf

The above command should yield the following output:
-rw-r----- 1 root root 993 Mar 11 07:04 /etc/syslog.conf

If the file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the ownership of the file to root using command: 
# chmod 0640 /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48842r755128_chk'
  tag severity: 'medium'
  tag gid: 'V-245563'
  tag rid: 'SV-245563r755130_rule'
  tag stig_id: 'AIX7-00-002146'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48797r755129_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
