control 'SV-246961' do
  title 'ONTAP must generate unique session identifiers using a FIPS 140-2-approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty hijacking the session or otherwise manipulating valid sessions.

This requirement is applicable to devices that use a web interface for device management.'
  desc 'check', 'Use "system services web show" to see if external web services is "true".

If ONTAP cannot be configured to recognize only system-generated session identifiers, this is a finding.'
  desc 'fix', 'Configure ONTAP to generate unique session identifiers using a FIPS 140-2-approved random number generator by "system services web modify -external false".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50393r769213_chk'
  tag severity: 'medium'
  tag gid: 'V-246961'
  tag rid: 'SV-246961r769215_rule'
  tag stig_id: 'NAOT-SC-000003'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-50347r769214_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
