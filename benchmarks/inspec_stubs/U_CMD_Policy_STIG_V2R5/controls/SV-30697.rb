control 'SV-30697' do
  title 'Mobile operating system (OS) based CMDs and systems must not be used to send, receive, store, or process classified messages unless specifically approved by NSA for such purposes and NSA approved transmission and storage methods are used.'
  desc 'DoDD 8100.2 states wireless devices will not be used for classified data unless approved for such use. Classified data could be exposed to unauthorized personnel.'
  desc 'check', 'Interview the ISSO. 

Verify written policy and training material exists (or requirement is listed on a signed user agreement) stating if and when CMDs can be used to transmit classified information. 

If written policy or training material does not exist, stating if and when CMDs can be used to receive, transmit, or process classified information, this is a finding.'
  desc 'fix', 'Publish written policy or training material stating if and when CMDs can be used to process, send, or receive classified information.'
  impact 0.7
  ref 'DPMS Target Smartphone Handheld Policy'
  tag check_id: 'C-31119r7_chk'
  tag severity: 'high'
  tag gid: 'V-24960'
  tag rid: 'SV-30697r5_rule'
  tag stig_id: 'WIR-SPP-005'
  tag gtitle: 'Classified data on CMDs'
  tag fix_id: 'F-27587r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
