control 'SV-243472' do
  title 'Separate smart cards must be used for Enterprise Admin (EA) and Domain Admin (DA) accounts from smart cards used for other accounts.'
  desc 'A separate smart card for Enterprise Admin and Domain Admin accounts eliminates the automatic exposure of the private keys for the EA/DA accounts to less secure user platforms when the other accounts are used.  Having different certificates on one card does not provide the necessary separation.  The same smart card may be used by an administrator for both EA and DA accounts.'
  desc 'check', 'Verify separate smart cards are used for EA and DA accounts from smart cards used for other accounts.  EA and DA accounts may be on the same smart card but must be separate from any other accounts.  If separate smart cards for EA and DA accounts from other accounts are not used, this is a finding.'
  desc 'fix', 'Use separate smart cards for EA and DA accounts from smart cards used for other accounts.  EA and DA accounts may be on the same smart card but must be separate from any other accounts.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46747r723449_chk'
  tag severity: 'medium'
  tag gid: 'V-243472'
  tag rid: 'SV-243472r723451_rule'
  tag stig_id: 'AD.0009'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46704r723450_fix'
  tag 'documentable'
  tag legacy: ['V-43648', 'SV-56469']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
