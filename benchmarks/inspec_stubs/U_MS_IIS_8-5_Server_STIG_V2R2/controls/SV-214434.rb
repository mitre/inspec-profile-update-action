control 'SV-214434' do
  title 'The IIS 8.5 web server must be tuned to handle the operational requirements of the hosted application.'
  desc 'A Denial of Service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc 'check', 'If the IIS 8.5 web server is not hosting any applications, this is Not Applicable.

If the IIS 8.5 web server is hosting applications, consult with the System Administrator to determine risk analysis performed when application was written and deployed to the IIS 8.5 web server.

Obtain documentation on the configuration.

Verify, at a minimum, the following tuning settings in the registry.

Access the IIS 8.5 web server registry.

Verify the following values are present and configured. The required setting depends upon the requirements of the application. 

Recommended settings are not provided as these settings have to be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\
"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"

If explicit settings are not configured for "URIEnableCache", "UriMaxUriBytes" and "UriScavengerPeriod", this is a finding.'
  desc 'fix', 'Access the IIS 8.5 web server registry.

Verify the following values are present and configured. The required setting depends upon the requirements of the application. These settings have to be explicitly configured to show a conscientious tuning has been made.

Navigate to HKLM\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\

Configure the following registry keys to levels to accommodate the hosted applications.

"URIEnableCache"
"UriMaxUriBytes"
"UriScavengerPeriod"'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15644r570457_chk'
  tag severity: 'medium'
  tag gid: 'V-214434'
  tag rid: 'SV-214434r539437_rule'
  tag stig_id: 'IISW-SV-000151'
  tag gtitle: 'SRG-APP-000435-WSR-000148'
  tag fix_id: 'F-15642r570458_fix'
  tag 'documentable'
  tag legacy: ['SV-91451', 'V-76755']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
