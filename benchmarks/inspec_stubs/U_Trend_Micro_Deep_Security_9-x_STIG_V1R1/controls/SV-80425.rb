control 'SV-80425' do
  title 'Trend Deep Security must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 

The methods employed to meet this requirement will vary depending upon the technology the application utilizes. However, a variety of technologies exist to limit or, in some cases, eliminate the effects of application related DoS attacks. Employing increased capacity and bandwidth combined with specialized application layer protection devices and service redundancy may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure excess capacity, bandwidth, or other redundancy is managed to limit the effects of information flooding types of Denial of Service (DoS) attacks.

Review the “CPU Usage Level” under Administration >> System Settings >> Advanced >> CPU Usage During Recommendation Scans.

Depending on resource capabilities for monitored agent scans, it may be necessary to limit the “CPU Usage Level” from High to Low. 

If the setting is not configured in accordance with the SA best practice recommendation this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.

Configure the “CPU Usage Level” in accordance with the SA best practice under Administration >> System Settings >> Advanced >> CPU Usage During Recommendation Scans.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65935'
  tag rid: 'SV-80425r1_rule'
  tag stig_id: 'TMDS-00-000190'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-72011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
