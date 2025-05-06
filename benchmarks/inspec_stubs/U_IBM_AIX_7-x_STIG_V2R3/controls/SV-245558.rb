control 'SV-245558' do
  title 'The AIX /etc/hosts file must be group-owned by root.'
  desc 'Unauthorized group ownership of the /etc/hosts file can lead to the ability for a malicious actor to redirect traffic to servers of their choice. It is also possible to use the /etc/hosts file to block detection by security software by blocking the traffic to all the download or update servers of well-known security vendors.'
  desc 'check', 'Check the group ownership of /etc/hosts using command:
# ls -al /etc/hosts

The above command should yield the following output:
-rw-r----- 1 root root 993 Mar 11 07:04 /etc/hosts

If the file is not group-owned by root, this is a finding'
  desc 'fix', 'Change the ownership of the file to root using command: 
# chgrp root /etc/hosts'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48837r755113_chk'
  tag severity: 'medium'
  tag gid: 'V-245558'
  tag rid: 'SV-245558r755115_rule'
  tag stig_id: 'AIX7-00-002141'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48792r755114_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
