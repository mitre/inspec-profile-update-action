control 'SV-254934' do
  title 'The Tanium application must offload audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on using multi-factor authentication.

2. Click "Modules" on the top of the banner of the console.

3. Click "Connect".

4. Review the configured connections under "Connections" section.

If no connection exists to send the "Tanium Audit Source" to a SIEM tool, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on using multi-factor authentication.

2. Click "Modules" on the top of the console.

3. Click "Connect".

4. Click "Create Connection".

5. In the "Configuration" section under "Source", select "Tanium Audit Source" as the source from the drop-down menu.

6. In the "Configuration" section under "Destination", select the desired destination and fill in the respective fields.

7. In the "Configure Output" section under "Format", select the desired file format type.

8. In the "Schedule" section, select the desired schedule.

9. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58547r867700_chk'
  tag severity: 'medium'
  tag gid: 'V-254934'
  tag rid: 'SV-254934r867702_rule'
  tag stig_id: 'TANS-AP-000865'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-58491r867701_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
