control 'SV-24998' do
  title 'The site must have a contingency for emergency administration of the system.'
  desc 'The built-in administrator account, as a well known account subject to attack, is disabled by default and per STIG requirements.  Domain administrative accounts on domain-joined systems should provide sufficient availability for administering a system.  A site with limited administrators must ensure they have a contingency for administering a non-domain system.'
  desc 'check', 'Determine if there is a contingency for administering a non-domain system with limited administrators.  An emergency administrator account must be documented with the ISSO, and it must be stored with its password in a secure location.  

If there is no contingency for administering a system in an emergency, this is a finding.'
  desc 'fix', 'Create a contingency plan for administering a system.  Document any emergency administrator account with the ISSO and store the account information in a secure location.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62083r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14224'
  tag rid: 'SV-24998r3_rule'
  tag gtitle: 'Backup Administrator Account'
  tag fix_id: 'F-66981r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
