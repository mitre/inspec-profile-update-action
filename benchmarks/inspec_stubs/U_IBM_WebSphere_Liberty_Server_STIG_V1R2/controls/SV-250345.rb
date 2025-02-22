control 'SV-250345' do
  title 'The WebSphere Liberty Server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Larger authentication cache timeout values can increase security risks. For example, a user who is revoked can still log in by using a credential that is cached in the authentication cache until the cache is refreshed.

Smaller authentication cache timeout values can affect performance. When this value is smaller, the Liberty Server accesses the user registry or repository more frequently.

Larger numbers of entries in the authentication cache, which is caused by an increased number of users, increases the memory usage of the authentication cache. Thus, the application server might slow down and affect performance.

If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Review system security plan and identify the cache timeout parameters for authentication. The  value for admin timeout is 10 minutes. However, a case-by-case exception based on operational requirements can be configured with AO acceptance. 

As a privileged user with access to server.xml, review the file and verify the authCache timeout parameter is configured for 10 minutes.

grep -i authcache server.xml

EXAMPLE:
<authCache initialSize="100" maxSize="50000" timeout="10m"/>

If the authCache timeout parameter is not configured for 10 minutes, or the AO has not accepted the risk for extending the timeout period specified, this is a finding.'
  desc 'fix', 'Edit the server.xml file and define the authCache timeout value as 10 minutes or AO approved value. Also ensure the appSecurity-2.0 feature is enabled.

EXAMPLE:

<featureManager> 
<feature>appSecurity-2.0</feature>
</featureManager> 

<authCache initialSize="100" maxSize="50000" timeout="10m"/>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53780r795086_chk'
  tag severity: 'medium'
  tag gid: 'V-250345'
  tag rid: 'SV-250345r862994_rule'
  tag stig_id: 'IBMW-LS-000970'
  tag gtitle: 'SRG-APP-000400-AS-000246'
  tag fix_id: 'F-53734r862993_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
