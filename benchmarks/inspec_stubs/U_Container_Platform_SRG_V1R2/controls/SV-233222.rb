control 'SV-233222' do
  title 'The container platform must protect against or limit the effects of all types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the container platform to mitigate the impact of DoS attacks that have occurred. For each container platform component, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting runtime processes or restricting the number of sessions the container platform runtime open, limiting container resources to memory and CPU).

Processes are an important indicator of security-and operations-relevant container activity. Process names and their arguments provide important visibility into a container’s activity. If an image includes non-default aliases or renamed binaries, attackers will still attempt to use well-known names.

The same malicious or unwanted activity might affect multiple deployments across different applications or environments. Staff investigating a potential incident need to find those exposures quickly.'
  desc 'check', 'Review documentation and configuration to determine if the container platform can protect against or limit the effects of all types of DoS attacks by employing defined security safeguards against resource depletion. Examples of resource limits are on memory, storage, and CPU. 

If the container platform cannot be configured to protect against or limit the effects of all types of DoS, this is a finding.'
  desc 'fix', 'Configure the container platform to protect against or limit the effects of all types of DoS attacks by employing defined security safeguards. Safeguards such as resource limits on memory, storage, and CPU can be used.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36158r601815_chk'
  tag severity: 'medium'
  tag gid: 'V-233222'
  tag rid: 'SV-233222r601816_rule'
  tag stig_id: 'SRG-APP-000435-CTR-001070'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-36126r601154_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
