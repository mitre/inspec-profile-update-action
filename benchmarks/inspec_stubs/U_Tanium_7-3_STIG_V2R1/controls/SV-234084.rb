control 'SV-234084' do
  title 'The Tanium Detect must be configured to receive IOC streams only from trusted sources.'
  desc 'An IOC stream is a series or stream of intel that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Detect can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the "Tanium Detect" module is being used, if not this is Not Applicable.

Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Detect".

Expand the left menu.

Click the "Management" tab.

Select "Sources".

Verify all configured Detect Streams are configured to a documented trusted source.

If any configured Detect Stream is configured to a stream that has not been documented as trusted, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Detect".

Expand the left menu.

Click the "Management" tab.

Select "Sources".

Click "New Source".

Select the specified Source from the list.

Fill out the specified information. 

Select "Create".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37269r610752_chk'
  tag severity: 'medium'
  tag gid: 'V-234084'
  tag rid: 'SV-234084r612749_rule'
  tag stig_id: 'TANS-SV-000008'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37234r610753_fix'
  tag 'documentable'
  tag legacy: ['SV-102241', 'V-92139']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
