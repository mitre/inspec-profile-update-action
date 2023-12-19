control 'SV-30700' do
  title 'The mobile device system administrator must perform a wipe command on all new or reissued CMDs and a STIG-compliant IT policy will be pushed to the device before issuing it to DoD personnel.'
  desc 'Malware can be installed on the device at some point between shipping from the factory and delivery to DoD.  The malware could result in the compromise of sensitive DoD information or result in the introduction of malware within the DoD network.'
  desc 'check', 'Detailed Policy Requirements: 
The CMD system administrator must perform a wipe command on all new or reissued CMDs, reload system software, and load a STIG-compliant security policy on the CMD before issuing it to DoD personnel and placing the device on a DoD network.   The intent is to return the device to the factory state before the DoD software baseline is installed.

When wireless activation is performed, the activation password is passed to the user in a secure manner (e.g., activation password is encrypted and emailed to an individual). 

Check Procedures: 
Interview the ISSO. Verify required procedures are followed. If required procedures were not followed, this is a finding.'
  desc 'fix', 'Perform a wipe command on all new or reissued mobile devices.'
  impact 0.3
  ref 'DPMS Target Smartphone Handheld Policy'
  tag check_id: 'C-31126r7_chk'
  tag severity: 'low'
  tag gid: 'V-24963'
  tag rid: 'SV-30700r5_rule'
  tag stig_id: 'WIR-SPP-008-01'
  tag gtitle: 'CMD provisioning-01'
  tag fix_id: 'F-27597r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
