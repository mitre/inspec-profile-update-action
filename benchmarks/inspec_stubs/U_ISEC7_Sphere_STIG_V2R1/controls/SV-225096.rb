control 'SV-225096' do
  title 'The ISEC7 Sphere server must be maintained at a supported version.'
  desc 'Versions of ISEC7 Sphere server are maintained by ISEC7 for specific periods of time. Unsupported versions will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

A list of supported ISEC7 Sphere server versions is maintained by ISEC7 here: https://www.isec7-us.com/emm-suite-mobile-monitoring'
  desc 'check', 'Review the ISEC7 Sphere server version after logging into the console. Correlate the version with the latest supported version of ISEC7 Sphere server.

If the installed version of ISEC7 Sphere server is not a supported version, this is a finding.'
  desc 'fix', 'The administrator must check https://www.isec7-us.com/emm-suite-mobile-monitoring
 for the latest supported and unsupported versions of software.

Once confirmed, the administrator must update ISEC7 Sphere server to the latest supported version.'
  impact 0.7
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26788r466190_chk'
  tag severity: 'high'
  tag gid: 'V-225096'
  tag rid: 'SV-225096r505933_rule'
  tag stig_id: 'ISEC-00-000100'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-26776r466191_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
