control 'SV-206842' do
  title 'The Voice Video Session Manager must provide centralized management of session (call) records.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack. The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Network components requiring centralized audit log management must have the capability to support centralized management.

Session records for Voice Video systems are generally handled in a similar fashion to audit records for other systems and are used for billing, usage analysis, and record support for actions taken. These detailed records are typically produced by the session manager.'
  desc 'check', 'Verify the Voice Video Session Manager provides centralized management of session records. Centralized management of session records may be a function of the Voice Video Session Manager or offloaded to an ancillary device. When records are offloaded, the Voice Video Session Manager must provide configuration settings to connect to the ancillary device.

If the Voice Video Session Manager does not provide centralized management of session records, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to provide centralized management of session records.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7097r364715_chk'
  tag severity: 'medium'
  tag gid: 'V-206842'
  tag rid: 'SV-206842r508661_rule'
  tag stig_id: 'SRG-NET-000333-VVSM-00028'
  tag gtitle: 'SRG-NET-000333'
  tag fix_id: 'F-7097r364716_fix'
  tag 'documentable'
  tag legacy: ['V-62119', 'SV-76609']
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
