control 'SV-250663' do
  title 'The system must ensure the vpxuser auto-password change meets policy.'
  desc 'By default, the vpxuser password will be automatically changed by vCenter every 30 days. Ensure this setting meets your policies; if not, configure to meet password aging policies. 

NOTE: It is very important the password aging policy not be shorter than the default interval that is set to automatically change the vpxuser password, to preclude the possibility that vCenter might get locked out of an ESXi host.'
  desc 'check', 'From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Verify that the "VirtualCenter.VimPasswordExpirationInDays" keyword is set to 60 or less. The default keyword value is 30 days and it is strongly recommended that this value not be changed from "30".

If the "VirtualCenter.VimPasswordExpirationInDays" keyword setting is greater than 60, this is a finding.'
  desc 'fix', 'From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Set the "VirtualCenter.VimPasswordExpirationInDays" to 60 or less. Note that it is strongly recommended that this value not be changed from "30".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54098r798986_chk'
  tag severity: 'medium'
  tag gid: 'V-250663'
  tag rid: 'SV-250663r798988_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000145'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54052r798987_fix'
  tag 'documentable'
  tag legacy: ['V-39301', 'SV-51117']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
