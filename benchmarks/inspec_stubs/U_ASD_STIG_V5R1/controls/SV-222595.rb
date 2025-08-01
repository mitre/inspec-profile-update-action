control 'SV-222595' do
  title 'The web service design must include redundancy mechanisms when used with high-availability systems.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time.

The methods employed to meet this requirement will vary depending upon the technology the application utilizes. However, a variety of technologies exist to limit or, in some cases, eliminate the effects of application related DoS attacks. Employing increased capacity and bandwidth combined with specialized application layer protection devices and service redundancy may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Interview the application administrator and review the system documentation to determine if the application has been designated as a high availability system and if the application is designed to operate in a high availability environment.

If the application has not been designated as a high availability system, this requirement is not applicable.

Review the application architecture documentation and identify solutions that provide application DoS protections. 

Verify the application has been built to work in a clustered or otherwise high availability environment in accordance with documented availability requirements.

This includes:

- load balancers
- redundant systems such as multiple web, application servers or DB servers
- high bandwidth or redundant data circuits
- multiple data centers (geographic dispersal)
- server clusters

If the application has been designated as high availability but the architecture is not built to high availability standards, this is a finding.'
  desc 'fix', 'Build the application to address issues that are found in a redundant environment and utilize redundancy mechanisms to provide high availability.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24265r493693_chk'
  tag severity: 'medium'
  tag gid: 'V-222595'
  tag rid: 'SV-222595r508029_rule'
  tag stig_id: 'APSC-DV-002410'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-24254r493694_fix'
  tag 'documentable'
  tag legacy: ['V-70241', 'SV-84863']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
