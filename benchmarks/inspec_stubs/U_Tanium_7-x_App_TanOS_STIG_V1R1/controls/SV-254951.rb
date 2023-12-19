control 'SV-254951' do
  title 'The application must, at a minimum, offload interconnected systems in real time and offload standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Select "Connect".

4. Review the "Connections" sections for source "Tanium Audit Source".

If necessary, filter the connections by filtering by "Source" and the term "Audit".

5. Select "Audit" from list.

6. In the Summary section, verify the "State" is "Enabled" and the "Next Run" value is less than "7" days.

If no results are returned, this is a finding. 

If results are returned but the state is not "Enabled", this is a finding.

If the schedule duration is more than one week, this is a finding.

If a schedule is not set, this is a finding.'
  desc 'fix', '1.Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.
 
2. Click "Modules" on the top navigation banner.
 
3. Select "Connect".

4. Click "Create Connection".

5. Enter "Name".

6. Enter "Description".

7. In the "Configuration" section, select "Source: Tanium Audit Source" and then under "Basic" options select appropriate audits.

8. In the Destination section, select a source from the drop-down menu. 

9. Enter "Destination Name".

10. Enter "Host".

11. Select "Network Protocol", then "TCP" or "UDP".

12. Enter "Port".

13. In the Schedule section, select "Enable Schedule".

14. Select "Basic".

15. Select the drop-down under "Frequency" and choose, "One run per day, on selected days of the week".

16. Select a day.

17. Select a time.

18. Select "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58564r867751_chk'
  tag severity: 'medium'
  tag gid: 'V-254951'
  tag rid: 'SV-254951r870364_rule'
  tag stig_id: 'TANS-AP-001405'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-58508r870364_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
