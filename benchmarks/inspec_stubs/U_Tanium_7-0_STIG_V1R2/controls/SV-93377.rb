control 'SV-93377' do
  title 'The Tanium IOC Detect must be configured to receive IOC streams only from trusted sources.'
  desc 'An IOC stream is a series or "stream" of IOCs that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. IOC Detect can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "IOC Detect".

Along the top right side of the interface, click on the icon with the gear.

Select "IOC Streams" from the headers within the "Settings" window.

Verify all configured IOC Detect Streams are configured to a documented trusted source.

If any configured IOC Detect Stream is configured to a stream that has not been documented as trusted, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "IOC Detect".

Along the top right side of the interface, click on the icon with the gear.

Select "IOC Streams" from the headers within the "Settings" window.

Delete IOC streams that are configured to a non-trusted source, or reconfigure to point to a trusted source.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78671'
  tag rid: 'SV-93377r1_rule'
  tag stig_id: 'TANS-SV-000008'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-85407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
