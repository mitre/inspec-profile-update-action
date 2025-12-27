control 'SV-69029' do
  title 'The DNS server implementation must be configured to provide audit record generation capability for DoD-defined auditable events within all DNS server components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 

The DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server is configured to generate audit events for successful and unsuccessful logon attempts, privileged activities and system-level access.

If the DNS server is not configured to generate audit events for successful and unsuccessful logon attempts, privileged activities and system-level access, this is a finding.'
  desc 'fix', 'Configure the DNS server to generate audit events for successful and unsuccessful logon attempts, privileged activities and system-level access within all DNS server components.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55405r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54783'
  tag rid: 'SV-69029r1_rule'
  tag stig_id: 'SRG-APP-000089-DNS-000005'
  tag gtitle: 'SRG-APP-000089-DNS-000005'
  tag fix_id: 'F-59641r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
