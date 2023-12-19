control 'SV-253945' do
  title 'The Juniper EX switch must be configured with an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify that the network device is in compliance with this requirement. 

The currently running version is displayed at login and can be displayed at any time by running the "show version" (or "show version local" depending upon platform) command.

If the network device is not running an operating system release that is currently supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade the network device to an operating system that is supported by the vendor.

request system software add <supported installation package>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57397r843866_chk'
  tag severity: 'high'
  tag gid: 'V-253945'
  tag rid: 'SV-253945r879887_rule'
  tag stig_id: 'JUEX-NM-000680'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-57348r843867_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
