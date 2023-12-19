control 'SV-233230' do
  title 'The container platform must remove old components after updated versions have been installed.'
  desc 'Previous versions of container platform components that are not removed from the container platform after updates have been installed may be exploited by adversaries by causing older components to execute which contain vulnerabilities. When these components are deleted, the likelihood of this happening is removed.'
  desc 'check', 'Review container platform registry documentation and configuration to determine if organization-defined images contains latest approved vendor software image version. 

If organization-defined images do not contain the latest approved vendor software image version, this is a finding. 

Review container platform registry documentation and configuration to determine if organization-defined images are removed after updated versions have been installed. 

If organization-defined images are not removed after updated versions have been installed, this is a finding. 

Review container platform runtime documentation and configuration to determine if organization-define images are executing latest image version from the container platform registry. 

If container platform runtime is not executing latest organization-defined images from the container platform registry, this is a finding.'
  desc 'fix', 'Configure the container platform registry to update organization-defined images with current approved vendor version and remove obsolete images after updated versions have been installed. Configure the container platform runtime to execute latest organization-defined images from the container platform registry.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36166r601823_chk'
  tag severity: 'medium'
  tag gid: 'V-233230'
  tag rid: 'SV-233230r601824_rule'
  tag stig_id: 'SRG-APP-000454-CTR-001110'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-36134r601863_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
