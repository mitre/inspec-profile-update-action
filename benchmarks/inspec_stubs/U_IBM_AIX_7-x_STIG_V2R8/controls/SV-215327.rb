control 'SV-215327' do
  title 'AIX passwd.nntp file must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 for /etc/news/passwd.nntp may allow access to privileged information by system intruders or malicious users.'
  desc 'check', 'If NNTP is not being used, this is Not Applicable.

Check passwd.nntp file permissions using command:
# find / -name passwd.nntp -exec ls -lL {} \\; 

The above command may yield the following output:
-rw-------    1 root     system           19 Oct 16 10:46 /etc/news/passwd.nntp

If a "passwd.nntp" file has a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Change the mode of all the found passwd.nntp files that have mode more permissive than "0600" using command: 
# chmod 0600 <passwd.nntp_file>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16525r294432_chk'
  tag severity: 'medium'
  tag gid: 'V-215327'
  tag rid: 'SV-215327r508663_rule'
  tag stig_id: 'AIX7-00-003013'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16523r294433_fix'
  tag 'documentable'
  tag legacy: ['SV-101697', 'V-91599']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
