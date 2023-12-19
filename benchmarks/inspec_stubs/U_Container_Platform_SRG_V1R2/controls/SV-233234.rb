control 'SV-233234' do
  title 'The container platform runtime must have updates installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'The container platform runtime must be carefully monitored for vulnerabilities, and when problems are detected, they must be remediated quickly. A vulnerable runtime exposes all containers it supports, as well as the host itself, to potentially significant risk. Organizations should use tools to look for Common Vulnerabilities and Exposures (CVEs) vulnerabilities in the runtimes deployed, to upgrade any instances at risk, and to ensure that orchestrators only allow deployments to properly maintained runtimes.'
  desc 'check', 'Review documentation and configuration to determine if the container platform registry inspects and contains approved vendor repository latest images containing security-relevant updates within a timeframe directed by an authoritative source (IAVM, CTOs, DTMs, STIGs, etc.). 

If the container platform registry does not contain the latest image with security-relevant updates within the time period directed by the authoritative source, this is a finding.

The container platform registry should help the user understand where the code in the environment was deployed from and must provide controls that prevent deployment from untrusted sources or registries.'
  desc 'fix', 'Configure the container platform registry to use approved vendor repository to ensure latest images containing security-relevant updates are installed within the time period directed by the authoritative source.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36170r601829_chk'
  tag severity: 'medium'
  tag gid: 'V-233234'
  tag rid: 'SV-233234r601830_rule'
  tag stig_id: 'SRG-APP-000456-CTR-001130'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-36138r601190_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
