control 'SV-254888' do
  title 'Tanium Threat Response must be configured to receive IOC streams only from trusted sources.'
  desc 'Using trusted and recognized IOC sources may detect and prevent systems from becoming compromised. An IOC stream is a series or stream of intel that is imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Threat Response can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the Threat Response module is being used, if not this is Not Applicable.

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Threat Response".

4. Expand the left menu.

5. Click "Intel".

6. Select "Sources".

7. Verify all configured Threat Response Streams are configured to a documented trusted source.

If Threat Response is configured to a stream that has not been documented as trusted, this is a finding.'
  desc 'fix', 'Consult the documentation on trusted intel subscription feeds. 

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Threat Response".

4. Expand the left menu.

5. Click "Intel".

6. Select "Sources".

7. Click "New Source".

8. Select the specified Source from the list.

9. Fill out the specified information based on the documented trusted intel feeds.  

10. Select "Create".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58501r867562_chk'
  tag severity: 'medium'
  tag gid: 'V-254888'
  tag rid: 'SV-254888r867564_rule'
  tag stig_id: 'TANS-AP-000135'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-58445r867563_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
