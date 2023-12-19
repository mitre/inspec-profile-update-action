control 'SRG-NET-000512-VVEP-00101_rule' do
  title 'The Unified Communications Endpoint must be configured with a firmware release supported by the vendor.'
  desc 'Operating a device with outdated firmware may leave the device with unmitigated security vulnerabilities. Vendors routinely update and patch firmware to address vulnerabilities. Operating with current supported firmware mitigates the vulnerabilities known by the vendor.'
  desc 'check', 'Verify the firmware release installed on the Unified Communications Endpoint is currently supported by the vendor.

If the firmware release installed on the Unified Communications Endpoint is not currently supported by the vendor, this is a finding.'
  desc 'fix', 'Install a currently supported firmware release supplied by the vendor onto the Unified Communications Endpoint.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000512-VVEP-00101_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000512-VVEP-00101'
  tag rid: 'SRG-NET-000512-VVEP-00101_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00101'
  tag gtitle: 'SRG-NET-000512-VVEP-00101'
  tag fix_id: 'F-SRG-NET-000512-VVEP-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
