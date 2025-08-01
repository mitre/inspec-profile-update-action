control 'SV-257907' do
  title 'RHEL 9 /etc/passwd file must be group-owned by root.'
  desc 'The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify the group ownership of the "/etc/passwd" file with the following command:

$ sudo stat -c "%G %n" /etc/passwd 

root /etc/passwd

If "/etc/passwd" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file /etc/passwd to root by running the following command:

$ sudo chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61648r925706_chk'
  tag severity: 'medium'
  tag gid: 'V-257907'
  tag rid: 'SV-257907r925708_rule'
  tag stig_id: 'RHEL-09-232135'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61572r925707_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
