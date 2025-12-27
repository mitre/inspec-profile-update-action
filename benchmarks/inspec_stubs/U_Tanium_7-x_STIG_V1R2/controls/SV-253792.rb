control 'SV-253792' do
  title 'The Tanium application must offload audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log in using multifactor authentication.

2. Click "Modules" on the top of the banner of the console.

3. Click "Connect".

4. Review the configured Connections under "Connections" section.

If no Connections exist to send the "Tanium Audit Source" to a security information and event management (SIEM) tool, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log in using multifactor authentication.

2. Click "Modules" on the top of the console.

3. Click "Connect".

4. Click "Create Connection".

5. In the "Configuration" section under "Source", select "Tanium Audit Source" as the source from the drop-down menu.

6. In the "Configuration" section under "Destination", select the desired Destination and fill in the respective fields.

7. In the "Configure Output" section under "Format", select the desired file format type.

8. In the "Schedule" section, select the desired schedule.

9. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57244r842402_chk'
  tag severity: 'medium'
  tag gid: 'V-253792'
  tag rid: 'SV-253792r850193_rule'
  tag stig_id: 'TANS-00-001310'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-57195r842403_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
