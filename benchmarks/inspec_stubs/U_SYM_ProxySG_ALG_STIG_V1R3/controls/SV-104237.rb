control 'SV-104237' do
  title 'Symantec ProxySG providing user authentication intermediary services must restrict user authentication traffic to specific authentication servers.'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ProxySG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).

The ProxySG will not use any other authentication server that has not been explicitly configured, such as the primary and backup authentication servers."
  desc 'check', 'The ProxySG only sends user authentication traffic to explicitly configured authentication servers. Verify which authentication servers are configured.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.

If Symantec ProxySG providing user authentication intermediary services does not restrict user authentication traffic to specific authentication servers, this is a finding.'
  desc 'fix', 'Configure the ProxySG for user authentication.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication >> Windows Domain.
3. Click "Add New Domain" and follow prompts to join the Windows Domain.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93469r1_chk'
  tag severity: 'high'
  tag gid: 'V-94283'
  tag rid: 'SV-104237r1_rule'
  tag stig_id: 'SYMP-AG-000340'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-100399r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
