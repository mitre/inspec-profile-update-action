control 'SV-204815' do
  title 'The application server must protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

There are many examples of technologies that exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy or clustering, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server can protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing defined security safeguards.

If the application server cannot be configured to protect against or limit the effects of all types of DoS, this is a finding.'
  desc 'fix', 'Configure the application server to protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing defined security safeguards.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4935r283086_chk'
  tag severity: 'medium'
  tag gid: 'V-204815'
  tag rid: 'SV-204815r850867_rule'
  tag stig_id: 'SRG-APP-000435-AS-000163'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-4935r283087_fix'
  tag 'documentable'
  tag legacy: ['V-57529', 'SV-71805']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
