control 'SV-254197' do
  title 'Nutanix AOS must be configured so that all local interactive user home directories have mode "0750" or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  desc 'check', %q(Confirm Nutanix AOS has assigned home directory of all local interactive users has a mode of "0750" or less permissive.

Step 1. Determine interactive users
$ sudo cat $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
cat: /home/nutanix: Is a directory
cat: /home/admin: Is a directory

Step 2. Determine permissions on interactive users home directories.
$ sudo stat -c "%a %n" /home/admin
750 /home/admin

$ sudo stat -c "%a %n" /home/nutanix
750 /home/nutanix

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.)
  desc 'fix', 'Configure any interactive users home directory to have a mode of "0750" or less by running the command:

$ sudo chmod 0750 [path to interactive users home directory]'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57682r846677_chk'
  tag severity: 'medium'
  tag gid: 'V-254197'
  tag rid: 'SV-254197r846679_rule'
  tag stig_id: 'NUTX-OS-001100'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-57633r846678_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
