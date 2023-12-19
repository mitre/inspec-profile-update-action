control 'SV-95599' do
  title 'AAA Services must be configured to audit each authentication and authorization transaction.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Verify AAA Services are configured to audit each authentication and authorization transaction.

If AAA Services are not configured to audit each authentication and authorization transaction, this is a finding.'
  desc 'fix', 'Configure AAA Services to audit each authentication and authorization transaction.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80889'
  tag rid: 'SV-95599r1_rule'
  tag stig_id: 'SRG-APP-000089-AAA-000380'
  tag gtitle: 'SRG-APP-000089-AAA-000380'
  tag fix_id: 'F-87745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
