control 'SV-95857' do
  title 'The Central Log Server must be configured for centralized management of the events repository for the purposes of configuration, analysis, and reporting.'
  desc 'If the application is not configured to centrally manage the content captured in the log records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in log records must be managed from a central location (necessitating automation). Centralized management of log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application components requiring centralized audit log management must be configured to support centralized management.'
  desc 'check', 'Examine the configuration.

Verify that centralized management of the events repository is enabled and configured for all hosts and devices within the scope of coverage.

If the Central Log Server is not enabled to allow centralized management of the events repository for the purposes of configuration, analysis, and reporting, this is a finding.'
  desc 'fix', 'Configure access for management tools used by administrators at management workstations, particularly those used for remote access. This often uses user access profiles or remote access configuration to enable secure and authorized access to the Central Log Server.

Enable management from one or more management workstations or a secure browser.

Verify remote communications from the management station using a secure, approved version of the protocol (e.g., TLS). Limit access based on user role, location, or remote device wherever possible.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80803r1_chk'
  tag severity: 'low'
  tag gid: 'V-81143'
  tag rid: 'SV-95857r1_rule'
  tag stig_id: 'SRG-APP-000356-AU-000090'
  tag gtitle: 'SRG-APP-000356-AU-000090'
  tag fix_id: 'F-87917r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
