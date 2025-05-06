control 'SV-242258' do
  title 'The TippingPoint SMS must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify the operating system version under devices and version in the SMS Software under Admin and General is still under security support by Trend Micro on the https://tmc.tippingpoint.com/TMC/ support website. 

If the operating system version is not under support, this is a finding.'
  desc 'fix', 'The system owner must ensure that the operating system version under Devices and SMS Software under Admin and General is still under security support by Trend Micro on the https://tmc.tippingpoint.com/TMC/ support website.

1. Select Release >> Software, and select either SMS or TPS. 
2. The versions there will be the supported releases.
3. Ensure the site SMS and TPS have one of these supported releases.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45533r710779_chk'
  tag severity: 'medium'
  tag gid: 'V-242258'
  tag rid: 'SV-242258r710781_rule'
  tag stig_id: 'TIPP-NM-000620'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-45491r710780_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
