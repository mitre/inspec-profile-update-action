control 'SV-4108' do
  title 'The system does not generate an audit event when the audit log reaches a percent full threshold.'
  desc 'When the audit log reaches a given percent full, an audit event is written to the security log. The event ID is 523 and is recorded as a success audit under the category of System. This option may be especially useful if the audit logs are set to be cleared manually. A recommended setting would be 90 percent.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning” to “90” or less.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-4108'
  tag rid: 'SV-4108r1_rule'
  tag gtitle: 'Audit Log Warning Level'
  tag fix_id: 'F-28831r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECRR-1'
end
