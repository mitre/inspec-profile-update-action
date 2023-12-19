control 'SV-253780' do
  title 'The application must, at a minimum, offload interconnected systems in real time and offload standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner.

3. Select "Connect".

4. Review the "Connections" sections for Source "Tanium Audit Source".

If necessary, filter the connections by filtering by "Source" and the term "Audit".

5. Verify the "State" is "Enabled".

If no results are returned, this is a finding. 

If results are returned but the state is not "Enabled", this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.
 
2. Click "Modules" on the top navigation banner.
 
3. Select "Connect".

4. Click "Create Connection".

5. Enter "Name".

6. Enter "Description".

7. In the "Configuration" section, select Source: "Tanium Audit Source" and under "Basic" options, select appropriate audits.

8. In the "Destination" section, select a source from the drop-down menu. 

9. Enter "Destination Name".

10. Enter "Host".

11. Select "Network Protocol": "TCP" or "UDP".

12. Enter "Port".

13. Select "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57232r842366_chk'
  tag severity: 'medium'
  tag gid: 'V-253780'
  tag rid: 'SV-253780r850325_rule'
  tag stig_id: 'TANS-00-001025'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-57183r842367_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
