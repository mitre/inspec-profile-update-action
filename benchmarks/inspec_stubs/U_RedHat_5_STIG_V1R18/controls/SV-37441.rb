control 'SV-37441' do
  title 'The rsh daemon must not be running.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check to see if rshd is configured to run on startup.

Procedure:
# grep disable /etc/xinetd.d/rsh

If /etc/xinetd.d/rsh exists and rsh is found to be enabled, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/rsh and set "disable=yes".'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36113r1_chk'
  tag severity: 'high'
  tag gid: 'V-4687'
  tag rid: 'SV-37441r1_rule'
  tag stig_id: 'GEN003820'
  tag gtitle: 'GEN003820'
  tag fix_id: 'F-31359r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
