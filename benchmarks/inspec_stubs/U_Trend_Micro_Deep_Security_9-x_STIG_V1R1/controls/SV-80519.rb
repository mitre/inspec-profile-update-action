control 'SV-80519' do
  title 'Trend Deep Security must generate audit records when successful/unsuccessful accesses to objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server to ensure audit records are generated when successful/unsuccessful accesses to objects occur.

Interview the ISSO for a list of functions identified as objects that should be audited within the application “System Events.”

Verify the list against the Administration >> System Settings >> System Events tab. 

If the events are not set to “Record” and “Forward”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records when successful/unsuccessful accesses to objects occur.

Enable the necessary objects required for audit by selecting “Record” and “Forward” within the Administration >> System Settings >> System Events, system settings.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66029'
  tag rid: 'SV-80519r1_rule'
  tag stig_id: 'TMDS-00-000390'
  tag gtitle: 'SRG-APP-000507'
  tag fix_id: 'F-72105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
