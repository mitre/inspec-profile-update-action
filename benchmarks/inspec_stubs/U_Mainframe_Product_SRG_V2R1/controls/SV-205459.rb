control 'SV-205459' do
  title 'The Mainframe Product must provide audit record generation capability for DoD-defined auditable events within all application components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Examine Mainframe Product documentation.

Refer to NIST SP 800-53 AU-2 or the Risk Management Knowledge Service (RMKS) for DoD auditing events.

Examine configuration settings.

Compare available auditing events.

If available auditing events do not include all DoD-defined auditing events, this is a finding.

If auditing is not available for all components of the Mainframe Product, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to audit all DoD-defined auditing events within all Mainframe Product components.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5725r299610_chk'
  tag severity: 'medium'
  tag gid: 'V-205459'
  tag rid: 'SV-205459r395706_rule'
  tag stig_id: 'SRG-APP-000089-MFP-000114'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-5725r299611_fix'
  tag 'documentable'
  tag legacy: ['SV-82677', 'V-68187']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
