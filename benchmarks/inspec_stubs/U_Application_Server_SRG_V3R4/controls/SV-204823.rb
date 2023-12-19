control 'SV-204823' do
  title 'The application server must install security-relevant software updates within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes) to production systems after thorough testing of the patches within a lab environment. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server checks with a patch management system to install security-relevant software updates within a timeframe directed by an authoritative source.

If the application server does not install security-relevant patches within the time period directed by the authoritative source, this is a finding.'
  desc 'fix', 'Configure the application server to use a patch management system to ensure security-relevant updates are installed within the time period directed by the authoritative source.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4943r283110_chk'
  tag severity: 'medium'
  tag gid: 'V-204823'
  tag rid: 'SV-204823r879827_rule'
  tag stig_id: 'SRG-APP-000456-AS-000266'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-4943r283111_fix'
  tag 'documentable'
  tag legacy: ['SV-71837', 'V-57561']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
