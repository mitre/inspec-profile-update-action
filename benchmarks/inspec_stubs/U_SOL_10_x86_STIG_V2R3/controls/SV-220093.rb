control 'SV-220093' do
  title 'The rlogind service must not be running.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.

'
  desc 'check', 'Determine if the rlogind service is running. 
# svcs rlogin

If the rlogin service is enabled, this is a finding.'
  desc 'fix', 'Disable the rlogind service. 

# svcadm disable rlogin
# svcadm refresh inetd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21802r489832_chk'
  tag severity: 'medium'
  tag gid: 'V-220093'
  tag rid: 'SV-220093r603266_rule'
  tag stig_id: 'GEN003830'
  tag gtitle: 'SRG-OS-000505'
  tag fix_id: 'F-21801r489833_fix'
  tag satisfies: ['SRG-OS-000505', 'SRG-OS-000555', 'SRG-OS-000033']
  tag 'documentable'
  tag legacy: ['V-22432', 'SV-39863']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
