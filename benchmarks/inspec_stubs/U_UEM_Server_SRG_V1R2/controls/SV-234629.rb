control 'SV-234629' do
  title 'The UEM server must be configured to verify software updates to the server using a digital signature mechanism prior to installing those updates.'
  desc 'Unauthorized modifications to software or firmware may be indicative of a sophisticated, targeted cyber-attack. Cryptographic authentication includes, for example, verifying that software or firmware components have been digitally signed using certificates recognized and approved by organizations. Code signing is an effective method to protect against malicious code. 

Satisfies:FPT_TUD_EXT.1.3'
  desc 'check', 'Verify the UEM server verifies software updates to the server using a digital signature mechanism prior to installing those updates.

If the UEM server does not verify software updates to the server using a digital signature mechanism prior to installing those updates, this is a finding.'
  desc 'fix', 'Configure the UEM server to verify software updates to the server using a digital signature mechanism prior to installing those updates.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37814r851707_chk'
  tag severity: 'medium'
  tag gid: 'V-234629'
  tag rid: 'SV-234629r879850_rule'
  tag stig_id: 'SRG-APP-000479-UEM-000354'
  tag gtitle: 'SRG-APP-000479'
  tag fix_id: 'F-37779r615522_fix'
  tag 'documentable'
  tag cci: ['CCI-002740']
  tag nist: ['SI-7 (15)']
end
