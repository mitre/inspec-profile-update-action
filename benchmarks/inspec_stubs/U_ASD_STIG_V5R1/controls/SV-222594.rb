control 'SV-222594' do
  title 'The application must restrict the ability to launch Denial of Service (DoS) attacks against itself or other information systems.'
  desc 'Denial of Service (DoS) is a condition where a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Individuals of concern can include hostile insiders or external adversaries that have access or have successfully breached the information system and are using the system as a platform to launch cyber attacks on the application, the application host or other third-parties.

Application developers and application administrators must take the steps needed to ensure an application cannot be used to launch DoS attacks against the application itself, the application host or other systems and networks. 

Application developers should be cognizant that many attackers using DoS techniques will attempt to identify resource intensive processes and functions within the application.  For web applications, this can be application objects that perform database queries or other resource intensive tasks.  Improper application memory management can also lead to memory leaks which can exhaust system resources forcing a system or application restart.  

Limiting attempts to repeatedly execute application processes by validating the requests also reduces the ability to launch some DoS attacks.

For application administrators, ensuring network access controls are in place to protect the application host.

The methods employed to counter DoS risks are dependent upon the application layer methods that can be used to exploit it.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Ask the application administrator if any anti-DoS technology or anti-DoS emergency response services are deployed to protect the application.

Check for code review, penetration or vulnerability test results that attempt to DoS the application or use the application as a DoS tool.

Examine test results and testing configuration to ensure that the application was tested and the application was not reported as being susceptible to DoS attacks either from external sources or from the application itself. Also verify the testing results show that the application cannot be weaponized to attack other systems.

If the test results indicate the application is susceptible to DoS attacks or can be weaponized to attack other applications or systems, this is a finding.'
  desc 'fix', 'Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24264r561255_chk'
  tag severity: 'medium'
  tag gid: 'V-222594'
  tag rid: 'SV-222594r561257_rule'
  tag stig_id: 'APSC-DV-002400'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-24253r561256_fix'
  tag 'documentable'
  tag legacy: ['SV-84861', 'V-70239']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
