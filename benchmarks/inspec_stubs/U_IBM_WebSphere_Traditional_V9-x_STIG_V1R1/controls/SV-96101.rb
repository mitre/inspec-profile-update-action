control 'SV-96101' do
  title 'The WebSphere Application Server memory session settings must be defined according to application load requirements.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards. These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

There are many examples of technologies that exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy or clustering, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review System Security Plan documentation.

Identify the application load requirements defined by system owner.

Regular application user session timeout values are defined at the DoD level at 20 minutes.

An ISSO risk acceptance is required to deviate from that value.

If session timeout values are not set to "20" and an ISSO risk acceptance is provided, this is not a finding.

From the admin console, navigate to Servers >> all servers >> [web application server] >> Session management.

For every [web application server], verify maximum in-memory session count.

Verify "allow overflow" and "session timeout" are set according to application load requirements.

If they are not set according to application load requirements, this is a finding.'
  desc 'fix', 'From the admin console navigate to Servers >> all servers >> [web application server] >> Session management.

For every [web application server], set the "Maximum in-memory session count", "allow overflow", and "session timeout" values according to your organizational requirements.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81097r2_chk'
  tag severity: 'low'
  tag gid: 'V-81387'
  tag rid: 'SV-96101r1_rule'
  tag stig_id: 'WBSP-AS-001580'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-88173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
