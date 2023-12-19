control 'SV-80423' do
  title 'Trend Deep Security must restrict the ability of individuals to use information systems to launch organization-defined Denial of Service (DoS) attacks against other information systems.'
  desc 'DoS is a condition where a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Individuals of concern can include hostile insiders or external adversaries that have successfully breached the information system and are using the system as a platform to launch cyber attacks on third parties.

Applications and application developers must take the steps needed to ensure users cannot use an authorized application to launch DoS attacks against other systems and networks. For example, applications may include mechanisms that throttle network traffic so users are not able to generate unlimited network traffic via the application. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks.

The methods employed to counter this risk will be dependent upon the application layer methods that can be used to exploit it.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the ability of individuals to use information systems to launch organization-defined Denial of Service (DoS) attacks against other information systems is restricted.

Deep Security policies for Firewall Rules can be disruptive causing a denial of service to the environment if not properly configured.

It is imperative that access to the firewall rule policies be restricted to authorized personnel by enforcing least privileged within the Deep Security, “User management” settings.

If role-based access controls are not enforced within the Administration >> User management >> Roles >> [Policy Name] >> Properties >> Policy Rights, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to restrict the ability of individuals to use information systems to launch organization-defined Denial of Service (DoS) attacks against other information systems.

Configure the role-based access controls to prevent access to policy modifications within the Administration >> User management >> Roles >> [Policy Name] >> Properties >> Policy Rights.  The “Edit” option should only be enabled to authorized users.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65933'
  tag rid: 'SV-80423r1_rule'
  tag stig_id: 'TMDS-00-000185'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-72009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
