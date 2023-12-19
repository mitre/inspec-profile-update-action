control 'SV-48452' do
  title 'Near Field Communications (NFC) chips must be disabled.'
  desc 'Various connection ports can provide additional attack vectors to a system or expose sensitive information and should be limited.'
  desc 'check', 'Verify NFC is turned off.   View status in device manager or NFC management application.
IF NFC is not disabled, this is a finding.

If the system does not have NFC, this is not applicable.'
  desc 'fix', 'Disable NFC in device manager.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45116r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36768'
  tag rid: 'SV-48452r2_rule'
  tag stig_id: 'WN08-MO-000012'
  tag gtitle: 'WN08-MO-000012'
  tag fix_id: 'F-41580r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
