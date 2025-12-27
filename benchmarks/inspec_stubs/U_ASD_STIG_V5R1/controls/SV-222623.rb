control 'SV-222623' do
  title 'The ISSO must report all suspected violations of IA policies in accordance with DoD information system IA procedures.'
  desc 'Violations of IA policies must be reviewed and reported. If there are no policies regarding the reporting of IA violations, IA violations may not be tracked or addressed in a proper manner.'
  desc 'check', 'Interview the application representative and review the SOPs to ensure that violations of IA policies are analyzed and reported.
 
If there is no policy for reporting IA violations, this is a finding.'
  desc 'fix', 'Create and maintain a policy to report IA violations.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24293r493777_chk'
  tag severity: 'medium'
  tag gid: 'V-222623'
  tag rid: 'SV-222623r508029_rule'
  tag stig_id: 'APSC-DV-002920'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24282r493778_fix'
  tag 'documentable'
  tag legacy: ['V-70301', 'SV-84923']
  tag cci: ['CCI-000366', 'CCI-000149']
  tag nist: ['CM-6 b', 'AU-6 b']
end
