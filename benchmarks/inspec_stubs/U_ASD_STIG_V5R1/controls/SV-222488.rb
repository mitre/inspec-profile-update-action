control 'SV-222488' do
  title 'The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.'
  desc 'The ability to specify the event criteria that are of interest provides the persons reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded.

Events of interest can be identified by the content of specific audit record fields including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific information system component. This requires applications to provide the capability to customize audit record reports based on organization-defined criteria.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture and logging configuration.

Identify the application components and the logs associated with the components as well as the locations of the logs.

If the application utilizes a centralized logging system that provides the capability to filter log events based upon the following events, this requirement is not applicable.

Review the application log management utility.

Ensure the application provides the ability to filter on audit events based upon the following minimum criteria:

Users: e.g., specific users or groups
Event types:
Event dates and time:
System resources involved: e.g., application components or modules.
IP addresses:
Information objects accessed:
Event level categories: e.g., high, critical, warning, error
Key words: e.g., a specific search string

Additional details may be logged as needed or prescribed by operational requirements.

If the application does not provide the ability to filter audit events, this is a finding.'
  desc 'fix', 'Configure the application filters to search event logs based on defined criteria.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24158r493372_chk'
  tag severity: 'medium'
  tag gid: 'V-222488'
  tag rid: 'SV-222488r508029_rule'
  tag stig_id: 'APSC-DV-001140'
  tag gtitle: 'SRG-APP-000115'
  tag fix_id: 'F-24147r493373_fix'
  tag 'documentable'
  tag legacy: ['SV-84081', 'V-69459']
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
