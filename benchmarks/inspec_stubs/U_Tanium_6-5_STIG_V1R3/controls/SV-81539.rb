control 'SV-81539' do
  title 'The Tanium IOC Detect must be configured to receive IOC streams only from trusted sources.'
  desc 'An IOC stream is a series or “stream” of IOCs that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. IOC Detect can be configured to retrieve the manually pulled IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "IOC Detect".

Along the right column of the interface, click on the icon with the down arrow.

Verify all configured IOC Detect Streams are configured to a documented trusted source.

If any configured IOC Detect Stream is configured to a stream which has not been documented as trusted, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "IOC Detect".

Along the right column of the interface, click on the icon with the down arrow.

Delete IOC streams which are configured to non-trusted source, or re-configured to point to a trusted source.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67685r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67049'
  tag rid: 'SV-81539r1_rule'
  tag stig_id: 'TANS-SV-000008'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-73149r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
