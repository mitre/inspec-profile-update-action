control 'SV-237210' do
  title 'ColdFusion must limit the maximum number of CFC function requests.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

One way to cause a DoS for ColdFusion is to exhaust resources by using services that are not being monitored because of their nonuse by hosted applications.  One of these services is remote ColdFusion Component (CFC) requests.  Remote CFC requests allow ColdFusion components to be called directly from an http/https url.  If this feature is being used, the number of simultaneous requests should be tuned using load testing to find the optimal value for the setting.  When the feature is not in use, the maximum number must be set to 1.'
  desc 'check', 'Determine if CFC functions are being called directly from http/https for any hosted application.   This may be determined by interviewing the administrator or by reviewing hosted applications code, hosted application design documentation or ColdFusion baseline documentation.

If CFC requests are being used by hosted applications, this finding is not applicable.

Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.

If the CFC requests are not being used by hosted applications and "Maximum number of simultaneous CFC function requests" is not set to 1, this is a finding.'
  desc 'fix', 'If CFC requests are being used by hosted applications, this finding is not applicable.

Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Maximum number of simultaneous CFC function requests" to 1 and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40429r641723_chk'
  tag severity: 'medium'
  tag gid: 'V-237210'
  tag rid: 'SV-237210r641725_rule'
  tag stig_id: 'CF11-05-000187'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40392r641724_fix'
  tag 'documentable'
  tag legacy: ['SV-76983', 'V-62493']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
