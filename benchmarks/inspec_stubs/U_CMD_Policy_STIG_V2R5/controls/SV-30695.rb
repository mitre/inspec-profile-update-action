control 'SV-30695' do
  title 'Required procedures must be followed for the disposal of CMDs.'
  desc 'If appropriate procedures are not followed prior to disposal of a CMD, an adversary may be able to obtain sensitive DoD information or learn aspects of the configuration of the device that might facilitate a subsequent attack.'
  desc 'check', 'This requirement applies to mobile operating system (OS) CMDs.

Prior to disposing of a CMD (for example, if a CMD is transferred to another DoD or government agency), follow the disposal procedures found in the mobile operating system STIG Supplemental document. 

Interview the ISSO. 

Verify proper procedures are being followed and the procedures are documented. 

Check to see how retired, discarded, or transitioned CMDs were disposed of during the previous 6 – 12 months and verify compliance with requirements. 

If procedures are not documented or if documented, they were not followed, this is a finding.'
  desc 'fix', 'Follow required procedures prior to disposing of a CMD or transitioning it to another user.'
  impact 0.3
  ref 'DPMS Target Smartphone Handheld Policy'
  tag check_id: 'C-31118r8_chk'
  tag severity: 'low'
  tag gid: 'V-24958'
  tag rid: 'SV-30695r6_rule'
  tag stig_id: 'WIR-SPP-004'
  tag gtitle: 'Follow procedures for disposal of CMDs'
  tag fix_id: 'F-27586r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
