control 'SV-80369' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure only the ISSM (or individuals or roles appointed by the ISSM) is allowed to select which auditable events are to be audited.

Verify the following events within the Administration >> System Settings >> System Events, are set to “Record.”
660 Role Created 
661 Role Deleted 
662 Role Updated 
663 Roles Imported 
664 Roles Exported 

If these settings are not set to “Record”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful attempts to access privileges occur.

Go to Administration >> System Settings >> System Events, and set the following settings to “Record.”
660 Role Created 
661 Role Deleted 
662 Role Updated 
663 Roles Imported 
664 Roles Exported'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66527r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65879'
  tag rid: 'SV-80369r1_rule'
  tag stig_id: 'TMDS-00-000070'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-71955r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
