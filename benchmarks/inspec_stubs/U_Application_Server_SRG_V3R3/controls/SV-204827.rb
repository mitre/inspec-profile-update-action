control 'SV-204827' do
  title 'The application server must generate log records for privileged activities.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Privileged activities would occur through the management interface.  This interface can be web-based or can be command line utilities.  Whichever method is utilized by the application server, these activities must be logged.'
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records for privileged activities.

If log records are not generated for privileged activities, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records for privileged activities.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4947r283122_chk'
  tag severity: 'medium'
  tag gid: 'V-204827'
  tag rid: 'SV-204827r508029_rule'
  tag stig_id: 'SRG-APP-000504-AS-000229'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-4947r283123_fix'
  tag 'documentable'
  tag legacy: ['V-57445', 'SV-71717']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
