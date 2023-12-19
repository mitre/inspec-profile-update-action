control 'SV-233231' do
  title 'The container platform registry must remove old container images after updating versions have been made available.'
  desc 'Obsolete and stale images need to be removed from the registry to ensure the container platform maintains a secure posture. While the storing of these images does not directly pose a threat, they do increase the likelihood of these images being deployed. Removing stale or obsolete images and only keeping the most recent versions of those that are still in use removes any possibility of vulnerable images being deployed.'
  desc 'check', 'Review container platform registry documentation and configuration to determine if organization-defined images contains latest approved vendor software image version. 

If organization-defined images do not contain the latest approved vendor software image version, this is a finding. 

Review container platform registry documentation and configuration to determine if organization-defined images are removed after updated versions have been installed. 

If organization-defined images are not removed after updated versions have been installed, this is a finding. 

Review container platform runtime documentation and configuration to determine if organization-defined images are executing latest image version from the container registry. 

If container platform runtime is not executing latest organization-defined images from the container platform registry, this is a finding.'
  desc 'fix', 'Configure the container platform registry to update organization-defined images with current approved vendor version and remove obsolete images after updated versions have been installed. Configure the container platform runtime to execute latest organization-defined images from the container platform registry.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36167r601825_chk'
  tag severity: 'medium'
  tag gid: 'V-233231'
  tag rid: 'SV-233231r601826_rule'
  tag stig_id: 'SRG-APP-000454-CTR-001115'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-36135r601864_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
