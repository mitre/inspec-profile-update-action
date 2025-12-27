control 'SV-253844' do
  title 'The Tanium applications must be configured to filter audit records for events of interest based on organization-defined criteria.'
  desc 'The ability to specify the event criteria that are of interest enables those reviewing the logs to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded. 

Events of interest can be identified by the content of specific audit record fields including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or by specific information system component. This requires applications to provide the capability to customize audit record reports based on organization-defined criteria.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Click "Connections" under "Connections" section.

5. Filter by source and review event-based sources. 

If any event=based sources have a failed run for more than 72 hours, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Expand the left menu. 

5. Click "Connections". 

6. Click "Create Connection" or if importing, click "Import".

7. Give the "Connection" a name and description.

8. In the "Configuration" section, select "Event" as the source.

9. Select appropriate source under "Event Group" - any source to generate interest-based events (Discover, Asset, IM, THR, etc).

10. Select the appropriate events to send.

Note: Consult with the Tanium system administrator for the Destination.

11. Select "Listen for this Event".

12. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57296r842558_chk'
  tag severity: 'medium'
  tag gid: 'V-253844'
  tag rid: 'SV-253844r842560_rule'
  tag stig_id: 'TANS-SV-000010'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-57247r842559_fix'
  tag 'documentable'
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
