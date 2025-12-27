control 'SRG-NET-000333-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to provide centralized management of session (call) records.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack. The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Network components requiring centralized audit log management must have the capability to support centralized management.

Session records for Voice Video systems are generally handled in a similar fashion to audit records for other systems and are used for billing, usage analysis, and record support for actions taken. These detailed records are typically produced by the session manager.'
  desc 'check', 'Verify the Unified Communications Session Manager provides centralized management of session records. Centralized management of session records may be a function of the Unified Communications Session Manager or offloaded to an ancillary device. When records are offloaded, the Unified Communications Session Manager must provide configuration settings to connect to the ancillary device.

If the Unified Communications Session Manager does not provide centralized management of session records, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to provide centralized management of session records.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000333-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000333-VVSM-00101'
  tag rid: 'SRG-NET-000333-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000333-VVSM-00101'
  tag gtitle: 'SRG-NET-000333-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000333-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
