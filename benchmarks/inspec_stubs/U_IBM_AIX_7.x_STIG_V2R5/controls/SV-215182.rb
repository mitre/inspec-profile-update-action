control 'SV-215182' do
  title 'The regular users default primary group must be staff (or equivalent) on AIX.'
  desc "The /usr/lib/security/mkuser.default file contains the default primary groups for regular and admin users. Setting a system group as the regular users' primary group increases the risk that the regular users can access privileged resources."
  desc 'check', 'Check the default primary group for regular users:
# lssec -f /etc/security/mkuser.default -s user -a pgrp

The above command should yield the following output:
user pgrp=staff

If the above command shows that the primary group (pgrp) is not "staff", this is a finding.'
  desc 'fix', 'Set the default primary groups for regular to be "staff".
# chsec -f /etc/security/mkuser.default -s user -a pgrp=staff'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16380r293997_chk'
  tag severity: 'medium'
  tag gid: 'V-215182'
  tag rid: 'SV-215182r508663_rule'
  tag stig_id: 'AIX7-00-001016'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-16378r293998_fix'
  tag 'documentable'
  tag legacy: ['SV-101315', 'V-91215']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
