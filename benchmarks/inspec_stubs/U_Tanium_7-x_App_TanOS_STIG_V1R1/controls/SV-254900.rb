control 'SV-254900' do
  title 'The Tanium applications must provide the capability to filter audit records for events of interest based upon organization-defined criteria.'
  desc 'The ability to specify the event criteria of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded. 

Events of interest can be identified by the content of specific audit record fields including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific information system component. This requires applications to provide the capability to customize audit record reports based on organization-defined criteria.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Expand the left menu. 

5. Click "Connections".

5. Review the configured Connections.

If there are no configured connections, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Expand the left menu. 

5. Click "Connections". 

6. Click "Create Connection" or if importing, click "Import".

7. Give the "Connection" a name and description.

8. In the "Configuration" section, select "Event" as the source.

9. Select appropriate source under "Event Group". Any source to generate interest-based events (Discover, Asset, IM, THR, etc.). 

10. Select the appropriate events to send.

Note: Consult with the Tanium System Administrator for the Destination.

11. Select "Listen for this Event".

12. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58513r867598_chk'
  tag severity: 'medium'
  tag gid: 'V-254900'
  tag rid: 'SV-254900r867600_rule'
  tag stig_id: 'TANS-AP-000280'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-58457r867599_fix'
  tag 'documentable'
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
