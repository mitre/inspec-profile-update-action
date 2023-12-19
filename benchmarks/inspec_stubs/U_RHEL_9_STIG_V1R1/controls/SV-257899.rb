control 'SV-257899' do
  title 'RHEL 9 /etc/group file must be group-owned by root.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify the group ownership of the "/etc/group" file with the following command:

$ sudo stat -c "%G %n" /etc/group 

root /etc/group

If "/etc/group" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file /etc/group to root by running the following command:

$ sudo chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61640r925682_chk'
  tag severity: 'medium'
  tag gid: 'V-257899'
  tag rid: 'SV-257899r925684_rule'
  tag stig_id: 'RHEL-09-232095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61564r925683_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
