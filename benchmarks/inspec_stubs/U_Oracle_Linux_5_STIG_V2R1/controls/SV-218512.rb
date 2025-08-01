control 'SV-218512' do
  title 'The rsh daemon must not be running.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check to see if rshd is configured to run on startup.

Procedure:
# grep disable /etc/xinetd.d/rsh

If /etc/xinetd.d/rsh exists and rsh is found to be enabled, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/rsh and set "disable=yes".'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19987r555734_chk'
  tag severity: 'high'
  tag gid: 'V-218512'
  tag rid: 'SV-218512r603259_rule'
  tag stig_id: 'GEN003820'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-19985r555735_fix'
  tag 'documentable'
  tag legacy: ['V-4687', 'SV-64011']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
