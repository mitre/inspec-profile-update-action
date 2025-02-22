control 'SV-233210' do
  title 'Vulnerability scanning applications must implement privileged access authorization to all container platform components, containers, and container images for selected organization-defined vulnerability scanning activities.'
  desc 'In certain situations, the nature of the vulnerability scanning may be more intrusive, or the container platform component that is the subject of the scanning may contain highly sensitive information. Privileged access authorization to selected system components facilitates more thorough vulnerability scanning and protects the sensitive nature of such scanning.

The vulnerability scanning application must utilize privileged access authorization for the scanning account.'
  desc 'check', 'Validate that scanning applications have privileged access to container platform components, containers, and container images to properly perform vulnerability scans. 

If privileged access is not given to the scanning application, this is a finding.'
  desc 'fix', 'Configure the vulnerability scanning application to have privileged access to the container platform components, containers, and container images.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36146r601117_chk'
  tag severity: 'medium'
  tag gid: 'V-233210'
  tag rid: 'SV-233210r879787_rule'
  tag stig_id: 'SRG-APP-000414-CTR-001010'
  tag gtitle: 'SRG-APP-000414'
  tag fix_id: 'F-36114r601118_fix'
  tag 'documentable'
  tag cci: ['CCI-001067']
  tag nist: ['RA-5 (5)']
end
