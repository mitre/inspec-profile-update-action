control 'SV-76691' do
  title 'The layer 2 switch must have all disabled switch ports assigned to an unused VLAN.'
  desc 'It is possible that a disabled port that is assigned to a user or management VLAN becomes enabled by accident or by an attacker and as a result gains access to that VLAN as a member.'
  desc 'check', 'Review the switch configurations and examine all access switch ports.  Each access switch port not in use should have membership to an inactive VLAN that is not used for any purpose and is not allowed on any trunk links.

If there are any access switch ports not in use and not in an inactive VLAN, this is a finding.

Note: Switch ports configured for 802.1x are exempt from this requirement.'
  desc 'fix', 'Assign all switch ports not in use to an inactive VLAN.

Note: Switch ports configured for 802.1x are exempt from this requirement.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-63005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62201'
  tag rid: 'SV-76691r1_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000007'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-68121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
