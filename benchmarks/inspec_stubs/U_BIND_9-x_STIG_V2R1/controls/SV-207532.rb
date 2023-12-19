control 'SV-207532' do
  title 'A BIND 9.x server implementation must be running in a chroot(ed) directory structure.'
  desc 'With any network service, there is the potential that an attacker can exploit a vulnerability within the program that allows the attacker to gain control of the process and even run system commands with that control. One possible defense against this attack is to limit the software to particular quarantined areas of the file system, memory or both. This effectively restricts the service so that it will not have access to the full file system. If such a defense were in place, then even if an attacker gained control of the process, the attacker would be unable to reach other commands or files on the system. This approach often is referred to as a padded cell, jail, or sandbox. All of these terms allude to the fact that the software is contained in an area where it cannot harm either itself or others. A more technical term is a chroot(ed) directory structure.

BIND should be configured to run in a padded cell or chroot(ed) directory structure.'
  desc 'check', 'Verify the directory structure where the primary BIND 9.x Server configuration files are stored is running in a chroot(ed) environment:

# ps -ef | grep named

named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

If the output does not contain "-t <chroot_path>", this is a finding.'
  desc 'fix', 'Configure the BIND 9.x server to operate in a chroot(ed) directory structure.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7787r283650_chk'
  tag severity: 'low'
  tag gid: 'V-207532'
  tag rid: 'SV-207532r612253_rule'
  tag stig_id: 'BIND-9X-000001'
  tag gtitle: 'SRG-APP-000243-DNS-000034'
  tag fix_id: 'F-7787r283651_fix'
  tag 'documentable'
  tag legacy: ['SV-86987', 'V-72363']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
