control 'SV-206515' do
  title 'The Central Log Server must be configured to automatically create trouble tickets for organization-defined threats and events of interest as they are detected in real time (within seconds).'
  desc 'In most Central Log Server products today, log review (threat detection), can be automated by creating correlation content matching the organizational-defined Events of Interest (e.g., account change actions, privilege command use, and other AU and AC family controls) to automatically notify or automatically create trouble tickets for threats as they are detected in real time. Auditors have repeatedly expressed a strong preference for automated ticketing. They are also more likely to follow up on the threat and action items needed to address the detected issues if the ticketing process is automated.

This is a function provided by most enterprise-level SIEMs. If the Central Log Server does not provide this function, it must forward the log records to a log server that does.'
  desc 'check', 'Note: This is not applicable (NA) if the Central Log Server (e.g., syslog) does not perform analysis. 

Examine the configuration.

Verify the Central Log Server automatically creates trouble tickets for organization-defined threats and events of interest as they are detected in real time (within seconds).

If the Central Log Server is not configured to automatically create trouble tickets for organization-defined threats and events of interest as they are detected in real time (within seconds), this is a finding.'
  desc 'fix', 'Configure the Central Log Server to automatically create trouble tickets for organization-defined threats and events of interest as they are detected in real time (within seconds).'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6775r285786_chk'
  tag severity: 'medium'
  tag gid: 'V-206515'
  tag rid: 'SV-206515r401224_rule'
  tag stig_id: 'SRG-APP-000516-AU-000360'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-6775r285787_fix'
  tag 'documentable'
  tag legacy: ['SV-95899', 'V-81185']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
