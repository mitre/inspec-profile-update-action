control 'SV-220092' do
  title 'The rsh daemon must not be running.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.


'
  desc 'check', '# svcs network/shell
If the service is enabled, this is a finding.'
  desc 'fix', 'Disable the remote shell service and restart inetd.
Procedure:
# svcadm disable network/shell
# svcadm refresh inetd'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21801r489826_chk'
  tag severity: 'high'
  tag gid: 'V-220092'
  tag rid: 'SV-220092r603266_rule'
  tag stig_id: 'GEN003820'
  tag gtitle: 'SRG-OS-000505'
  tag fix_id: 'F-21800r489827_fix'
  tag satisfies: ['SRG-OS-000505', 'SRG-OS-000555', 'SRG-OS-000033']
  tag 'documentable'
  tag legacy: ['V-4687', 'SV-27435']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
