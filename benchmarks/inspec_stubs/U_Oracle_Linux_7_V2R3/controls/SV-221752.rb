control 'SV-221752' do
  title 'The Oracle Linux operating system must be configured so that the cron.allow file, if it exists, is group-owned by root.'
  desc 'If the group owner of the "cron.allow" file is not set to root, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Verify that the "cron.allow" file is group-owned by root.

Check the group owner of the "cron.allow" file with the following command:

# ls -al /etc/cron.allow
-rw------- 1 root root 6 Mar 5 2011 /etc/cron.allow

If the "cron.allow" file exists and has a group owner other than root, this is a finding.'
  desc 'fix', 'Set the group owner on the "/etc/cron.allow" file to root with the following command:

# chgrp root /etc/cron.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23467r419328_chk'
  tag severity: 'medium'
  tag gid: 'V-221752'
  tag rid: 'SV-221752r603260_rule'
  tag stig_id: 'OL07-00-021120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23456r419329_fix'
  tag 'documentable'
  tag legacy: ['SV-108347', 'V-99243']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
