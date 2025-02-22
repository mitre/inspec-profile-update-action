control 'SV-250664' do
  title 'The system must ensure the vpxuser password meets length policy.'
  desc 'The vpxuser password default length is 32 characters. Ensure this setting meets site policies; if not, configure to meet password length policies. Longer passwords make brute-force password attacks more difficult. The vpxuser password is added by vCenter, meaning no manual intervention is normally required. The vpxuser password length must never be modified to less than the default length of 32 characters.'
  desc 'check', 'The default minimum length for passwords is 14. The vpxuser password default length is 32 characters. The vpxuser password length must never be modified to less than the default length of 32 characters. From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Verify the "config.vpxd.hostPasswordLength" is set to 32 or greater.  Default is 32 characters.  

If the "config.vpxd.hostPasswordLength" setting is less than 32, this is a finding.'
  desc 'fix', 'From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Set the "config.vpxd.hostPasswordLength" to comply with site requirements.  Default is 32 characters. Note that the vpxuser password is added by vCenter, meaning no manual intervention is required. The vpxuser password length must never be modified to less than the default length of 32 characters.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54099r798989_chk'
  tag severity: 'medium'
  tag gid: 'V-250664'
  tag rid: 'SV-250664r798991_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000146'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54053r798990_fix'
  tag 'documentable'
  tag legacy: ['SV-51118', 'V-39302']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
