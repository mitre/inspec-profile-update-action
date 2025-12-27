control 'SV-233166' do
  title 'The container platform must provide the configuration for organization-identified individuals or roles to change the auditing to be performed on all components, based on all selectable event criteria within organization-defined time thresholds.'
  desc 'Auditing requirements may change per organization or situation within and organization. With the container platform allowing an organization to customize the auditing, an organization can decide to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real-time, within minutes, or within hours.

Modifying auditing within the container platform must be controlled to only those individuals or roles identified by the organization to modify auditable events.'
  desc 'check', "Review documentation and configuration setting. 

If the container platform does not provide the ability for users in authorized roles to reconfigure auditing at any time of the user's choosing, this is a finding. 

If changes in audit configuration cannot take effect until after a certain time or date, or until some event, such as a server restart, has occurred, and if that time or event does not meet the requirements specified by the organization, this is a finding."
  desc 'fix', 'Deploy a container platform that provides the ability for users in authorized roles to reconfigure auditing at any time. Deploy a container platform that allows audit configuration changes to take effect within the timeframe required by the organization and without involving actions or events that the organization rules unacceptable.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36102r601768_chk'
  tag severity: 'medium'
  tag gid: 'V-233166'
  tag rid: 'SV-233166r879887_rule'
  tag stig_id: 'SRG-APP-000516-CTR-000790'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36070r601868_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
