control 'SV-245561' do
  title 'The AIX /etc/syslog.conf file must be owned by root.'
  desc 'Unauthorized ownership of the /etc/syslog.conf file can lead to the ability for a malicious actor to alter or disrupt system logging activities. This can aid the malicious actor in avoiding detection and further their ability to conduct malicious activities on the system.'
  desc 'check', 'Check the ownership of /etc/syslog.conf using command:
# ls -al /etc/syslog.conf

The above command should yield the following output:
-rw-r----- 1 root system 993 Mar 11 07:04 /etc/syslog.conf

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the file to root using command: 
# chown root /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48840r818801_chk'
  tag severity: 'medium'
  tag gid: 'V-245561'
  tag rid: 'SV-245561r818803_rule'
  tag stig_id: 'AIX7-00-002144'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48795r818802_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
