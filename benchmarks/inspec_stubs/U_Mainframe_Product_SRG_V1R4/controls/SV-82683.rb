control 'SV-82683' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to access security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security objects, writes to SMF, and/or uses an external security manager (ESM) to generate audit records when successful/unsuccessful attempts to access security objects. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to access security objects.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68193'
  tag rid: 'SV-82683r1_rule'
  tag stig_id: 'SRG-APP-000492-MFP-000117'
  tag gtitle: 'SRG-APP-000492-MFP-000117'
  tag fix_id: 'F-74309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
