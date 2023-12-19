control 'SV-215194' do
  title 'The Group Identifiers (GIDs) reserved for AIX system accounts must not be assigned to non-system accounts as their primary group GID.'
  desc 'Reserved GIDs are typically used by system software packages. If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', 'From the command prompt, run the following command:

# more /etc/passwd 
root:!:0:0::/root:/usr/bin/ksh
daemon:!:1:1::/etc:
bin:!:2:2::/bin:
sys:!:3:3::/usr/sys:
adm:!:4:4::/var/adm:
nobody:!:4294967294:4294967294::/:
invscout:*:6:12::/var/adm/invscout:/usr/bin/ksh
srvproxy:*:203:0:Service Proxy Daemon:/home/srvproxy:/usr/bin/ksh
esaadmin:*:7:0::/var/esa:/usr/bin/ksh
sshd:*:212:203::/var/empty:/usr/bin/ksh
doejohn:*:704:1776::/home/doej:/usr/bin/ksh

Confirm all accounts with a primary GID of 99 and below are used by a system account. 

If a GID reserved for system accounts, 0 - 99, is used by a non-system account, this is a finding.'
  desc 'fix', 'Change the primary GID for non-system accounts that have reserved GIDs as their primary GIDs using the following command:
# chuser pgrp=<non_reserved_group_name> <non_system_user_name>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16392r294033_chk'
  tag severity: 'medium'
  tag gid: 'V-215194'
  tag rid: 'SV-215194r508663_rule'
  tag stig_id: 'AIX7-00-001035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16390r294034_fix'
  tag 'documentable'
  tag legacy: ['V-91623', 'SV-101721']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
