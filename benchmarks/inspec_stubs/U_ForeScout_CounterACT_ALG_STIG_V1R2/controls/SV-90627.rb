control 'SV-90627' do
  title 'If user authentication services are provided, CounterACT must restrict user authentication traffic to specific authentication server(s).'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by CounterACT as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'If CounterACT does not provide user authentication intermediary services, this is not applicable.

Verify CounterACT is configured to use a specific authentication server(s). 

1. Connect to the CounterACT Admin Console and log in.
2. Go to Tools >> Options >> User Directory.
3. Verify the User Directory is configured for Authentication. Select the configured directory (or directories) and on the General Tab ensure the "Use for Authentication" radio button is selected.
4. Verify the Hostname is correct for the assigned directory and then select "OK". (Select "Apply" if changes were made.)
5. Select the directory and then select test. Verify both tests past. 

If CounterACT does not restrict user authentication traffic to a specific authentication server(s), this is a finding.'
  desc 'fix', 'If user authentication service is provided by CounterACT, configure the use of a central directory service for user authentication.

1. Connect to the CounterACT Admin Console and log in.
2. Go to Tools >> Options >> User Directory.
3. Ensure the User Directory configured for Authentication. Select the configured directory (or directories) and on the General Tab ensure the "Use for Authentication" radio button is selected.
4. Ensure the Hostname is correct for the assigned directory and then select "OK". (Select "Apply" if changes were made.)
5. Select the directory and then select test. Ensure both tests passed.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75621r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75939'
  tag rid: 'SV-90627r1_rule'
  tag stig_id: 'CACT-AG-000007'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-82577r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
