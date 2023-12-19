control 'SV-15473' do
  title 'Two-factor authentication must be implemented to restrict access to all network elements.'
  desc 'Without secure management implemented with authenticated access controls, strong two-factor authentication, encryption of the management session and audit logs, unauthorized users may gain access to network managed devices compromised, large parts of the network could be incapacitated with only a few commands.'
  desc 'check', 'Review all network element configurations to ensure that an authentication server is being used. Then verify that a two-factor authentication method has been implemented. The RADIUS or TACACS server referenced in the configurations will call a two-factor authentication server.

If two-factor authentication is not being used to access all network elements, this is a finding.'
  desc 'fix', 'The network administrator must ensure strong two-factor authentication is being incorporated in the access scheme.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12939r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14723'
  tag rid: 'SV-15473r2_rule'
  tag stig_id: 'NET0445'
  tag gtitle: 'Two-factor authentication is not implemented'
  tag fix_id: 'F-14190r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
