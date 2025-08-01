control 'SV-246960' do
  title 'ONTAP must recognize only system-generated session identifiers.'
  desc 'Network device management web interfaces utilize sessions and session identifiers to control management interface behavior and administrator access. If an attacker can guess the session identifier or can inject or manually insert session information, the session may be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', 'Use "system services web show" to see if external web services is "true".

If ONTAP cannot be configured to recognize only system-generated session identifiers, this is a finding.'
  desc 'fix', 'Configure ONTAP to recognize only system-generated session identifiers by "system services web modify -external false".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50392r769210_chk'
  tag severity: 'medium'
  tag gid: 'V-246960'
  tag rid: 'SV-246960r769212_rule'
  tag stig_id: 'NAOT-SC-000002'
  tag gtitle: 'SRG-APP-000223-NDM-000269'
  tag fix_id: 'F-50346r769211_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
