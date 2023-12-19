control 'SV-253874' do
  title 'The Tanium application service must be protected from being stopped by a nonprivileged user.'
  desc 'Denial of service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc 'check', %q(Verify that to prevent a nonprivileged user from affecting the Tanium Server's ability to operate, the control of the service is restricted to the local administrators.

1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open the CMD prompt as admin.

4. Run "sc sdshow "Tanium Server".

If the string does not match "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)", this is a finding.

Note: Run the above on all other Tanium Servers, including Tanium Servers in an Active-Active pair.)
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open the CMD prompt as admin.

4. Run "sc sdset "Tanium Server" D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)".

5. Run the above on all other Tanium Servers, including Tanium Servers in an Active-Active pair.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57326r842648_chk'
  tag severity: 'medium'
  tag gid: 'V-253874'
  tag rid: 'SV-253874r850265_rule'
  tag stig_id: 'TANS-SV-000068'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-57277r842649_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
