control 'SV-93467' do
  title 'The Tanium web server must be tuned to handle the operational requirements of the hosted application.'
  desc 'Denial of service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

To prohibit an attacker from stopping the web server, the process ID (pid) of the web server and the utilities used to start/stop the web server must be protected from access by non-privileged users. By knowing the pid and having access to the web server utilities, a non-privileged user has a greater capability of stopping the server, whether intentionally or unintentionally.'
  desc 'check', 'As part of any Tanium install, Tanium has a tuning process that takes into account customer-provided inputs on the size of the deployment as well as characteristics of the network.

Obtain from Tanium the document that states the tuning settings for the particular installation.

If the organization cannot provide a server tuning document from the vendor, this is a finding.'
  desc 'fix', "Obtain the vendor tuning documentation for the deployment and include it in the system's documentation as proof of tuning."
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78337r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78761'
  tag rid: 'SV-93467r1_rule'
  tag stig_id: 'TANS-SV-000069'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-85503r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
