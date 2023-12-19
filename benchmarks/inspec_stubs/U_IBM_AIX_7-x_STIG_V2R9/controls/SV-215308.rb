control 'SV-215308' do
  title 'AIX system must require authentication upon booting into single-user and maintenance modes.'
  desc 'This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.'
  desc 'check', 'Verify that the "root" account has a password assigned:

# cut -d: -f1,2 /etc/passwd | grep root

root:!

If the "root" account is not listed with an "!", this is a finding.'
  desc 'fix', 'Assign the "root" account a password using passwd command while logged on as "root":
# passwd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16506r294375_chk'
  tag severity: 'medium'
  tag gid: 'V-215308'
  tag rid: 'SV-215308r508663_rule'
  tag stig_id: 'AIX7-00-002127'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16504r294376_fix'
  tag 'documentable'
  tag legacy: ['V-91575', 'SV-101673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
