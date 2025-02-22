control 'SV-68675' do
  title 'The ALG must be configured to support centralized management and configuration.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

Network components requiring centralized audit log management must have the capability to support centralized management.

The DoD requires centralized management of all network component audit record content.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG supports centralized management and configuration.

If the ALG does not support centralized management and configuration, this is a finding.'
  desc 'fix', 'Configure the ALG to support centralized management and configuration.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55045r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54429'
  tag rid: 'SV-68675r1_rule'
  tag stig_id: 'SRG-NET-000333-ALG-000049'
  tag gtitle: 'SRG-NET-000333-ALG-000049'
  tag fix_id: 'F-59283r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
