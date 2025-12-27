control 'SV-77269' do
  title 'The Palo Alto Networks security platform must not use Password Profiles.'
  desc 'Password profiles override settings made in the Minimum Password Complexity window.  If Password Profiles are used they can bypass password complexity requirements.'
  desc 'check', 'Go to Device >> Password Profiles
If there are configured Password Profiles, this is a finding.'
  desc 'fix', 'Go to Device >> Password Profiles
If the screen is blank (no configured Password Profiles), do nothing.

If there are configured Password Profiles, identify which accounts are using them and bring this to the attention of the ISSO immediately.
Delete the Password Profiles when authorized to make changes to the device in accordance with local change management policies.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63587r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62779'
  tag rid: 'SV-77269r1_rule'
  tag stig_id: 'PANW-NM-000142'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-68699r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
