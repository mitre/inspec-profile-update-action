control 'SV-215744' do
  title 'The BIG-IP Core implementation must be configured to limit the number of concurrent sessions to an organization-defined number for virtual servers.'
  desc 'Network element management includes the ability to control the number of users and user sessions that utilize a network element. Limiting the number of current sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. 

The organization-defined number of concurrent sessions must be the same as the requirements specified for the application for which it serves as intermediary.

This policy only applies to application gateways/firewalls (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', %q(If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core limits the number of concurrent sessions to an organization-defined number for virtual servers.

Review organizational Standard Operating Procedures (SOP) to ensure there is an organization-defined threshold for the maximum number of concurrent session for each application the BIG-IP Core serves as intermediary.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select a Virtual Server from the list to verify that the connection limit is set.

Select "Advanced" for "Configuration".

Review the following under the "Configuration" section.

Verify that 'Connection Limit' is set to the organization-defined number of concurrent connections and not set to zero (0).

Verify that "Connection Rate Limit" is set to the organization-defined number of concurrent connections per second and not set to zero (0).

If the BIG-IP Core is not configured to limit the number of concurrent sessions to an organization-defined number or is set to zero (0) for virtual servers, this is a finding.)
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure the appropriate Virtual Server(s) in the BIG-IP LTM module to limit concurrent sessions to the organization-defined number for virtual servers.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16936r291045_chk'
  tag severity: 'high'
  tag gid: 'V-215744'
  tag rid: 'SV-215744r557356_rule'
  tag stig_id: 'F5BI-LT-000029'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag fix_id: 'F-16934r291046_fix'
  tag 'documentable'
  tag legacy: ['SV-74699', 'V-60269']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
