control 'SV-245559' do
  title 'The AIX /etc/hosts file must have a mode of 0640 or less permissive.'
  desc 'Unauthorized permissions of the /etc/hosts file can lead to the ability for a malicious actor to redirect traffic to servers of their choice. It is also possible to use the /etc/hosts file to block detection by security software by blocking the traffic to all the download or update servers of well-known security vendors.'
  desc 'check', 'Check the mode of /etc/hosts using command:
# ls -al /etc/hosts

The above command should yield the following output:
-rw-r----- 1 root root 993 Mar 11 07:04 /etc/hosts

If the file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the ownership of the file to root using command: 
# chmod 0640 /etc/hosts'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48838r755116_chk'
  tag severity: 'medium'
  tag gid: 'V-245559'
  tag rid: 'SV-245559r755118_rule'
  tag stig_id: 'AIX7-00-002142'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48793r755117_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
