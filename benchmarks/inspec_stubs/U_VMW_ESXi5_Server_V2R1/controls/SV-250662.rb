control 'SV-250662' do
  title 'The system must ensure the vpxuser auto-password change meets policy.'
  desc 'By default, the vpxuser password will be automatically changed by vCenter every 30 days. Ensure this setting meets your policies; if not, configure to meet password aging policies. 

NOTE: It is very important the password aging policy not be shorter than the default interval that is set to automatically change the vpxuser password, to preclude the possibility that vCenter might get locked out of an ESXi host.'
  desc 'check', 'From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Verify that the "VirtualCenter.VimPasswordExpirationInDays" keyword is set to 60 or less. The default keyword value is 30 days and it is strongly recommended that this value not be changed from "30".

If the "VirtualCenter.VimPasswordExpirationInDays" keyword setting is greater than 60, this is a finding.'
  desc 'fix', 'From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Set the "VirtualCenter.VimPasswordExpirationInDays" to 60 or less. Note that it is strongly recommended that this value not be changed from "30".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54097r798983_chk'
  tag severity: 'medium'
  tag gid: 'V-250662'
  tag rid: 'SV-250662r798985_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000145'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54051r798984_fix'
  tag 'documentable'
  tag legacy: ['SV-51116', 'V-39300']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
