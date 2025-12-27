control 'SV-86095' do
  title 'The CA API Gateway providing user access control intermediary services must generate audit records showing starting and ending time for user access to the system.'
  desc %q(Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

This requirement applies to the ALG traffic management functions, such as content filtering or intermediary services. This does not apply to audit logs generated on behalf of the device (device management).

By default, the CA API Gateway audits all starting events for each Registered Service. An ending event can be generated through the use of a "logout service/API", which is called by the user's application at the time of logout or session termination. If the Registered Service/API already has the logout capability included, the ending event will be generated automatically at logout without the need for an additional logout service.)
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Verify that each Registered Service requiring starting and ending event auditing includes the logout/terminate session capability as part of the Registered Service/API. 

If it does not, this is a finding.'
  desc 'fix', %q(If any of the Registered Services/API's do not provide a logout/terminate session capability as part of the API, create and register a "Logoff" Registered Service and call this service from the user's application upon ending a session. This will automatically generate the ending event as required and be audited on the Gateway. 

For more details on registering and authoring services, refer to the “CA API Management Documentation Wiki" at https://wiki.ca.com/display/GATEWAY90/CA+API+Gateway+Home.)
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71471'
  tag rid: 'SV-86095r1_rule'
  tag stig_id: 'CAGW-GW-000870'
  tag gtitle: 'SRG-NET-000505-ALG-000039'
  tag fix_id: 'F-77791r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
