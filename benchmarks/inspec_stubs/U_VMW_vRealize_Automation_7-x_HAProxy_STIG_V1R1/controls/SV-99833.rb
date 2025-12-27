control 'SV-99833' do
  title 'HAProxy must set an inactive timeout on sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 

Acceptable values are "5" minutes for high-value applications, "10" minutes for medium-value applications, and "20" minutes for low-value applications.

HAProxy provides an appsession parameter, which will invalidate an inactive cookie after a configurable amount of time.'
  desc 'check', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Verify that each backend that sets a cookie is configured with the following:

appsession <cookie> len 64 timeout 5m

Note: The value for <cookie> is defined in the "cookie" option for each backend and may be different.

If the "appsession" option is not present or is not configured as shown, this is a finding.'
  desc 'fix', 'Navigate to and open the following files:

/etc/haproxy/conf.d/30-vro-config.cfg 
/etc/haproxy/conf.d/20-vcac.cfg

Navigate to each backend section that sets a cookie in each file.

Configure the backend with the following:

appsession <cookie> len 64 timeout 5m

Note: The value for <cookie> is defined in the "cookie" option for each backend and may be different.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89183'
  tag rid: 'SV-99833r1_rule'
  tag stig_id: 'VRAU-HA-000330'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-95925r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
