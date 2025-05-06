control 'SV-215195' do
  title 'UIDs reserved for system accounts must not be assigned to non-system accounts on AIX systems.'
  desc 'Reserved UIDs are typically used by system software packages. If non-system accounts have UIDs in this range, they may conflict with system software, possibly leading to the user having permissions to modify system files.'
  desc 'check', 'Check the UID assignments of all accounts using: 

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
doej:*:704:1776::/home/doej:/usr/bin/ksh

Confirm all accounts with a UID of 128 and below are used by a system account. 

If a UID reserved for system accounts (0-128) is used by a non-system account, this is a finding.'
  desc 'fix', 'Using the "usermod" command, change the UID numbers for non-system accounts with reserved UIDs (those less or equal to 128): 
# usermod -u <uid> [user_name]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16393r294036_chk'
  tag severity: 'medium'
  tag gid: 'V-215195'
  tag rid: 'SV-215195r508663_rule'
  tag stig_id: 'AIX7-00-001036'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16391r294037_fix'
  tag 'documentable'
  tag legacy: ['SV-101763', 'V-91665']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
