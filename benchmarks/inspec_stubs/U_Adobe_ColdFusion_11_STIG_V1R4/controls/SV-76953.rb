control 'SV-76953' do
  title 'The ColdFusion Administrator Console must be hosted on a management network.'
  desc 'ColdFusion consists of the Administrator Console and hosted applications.  By separating the Administrator Console from hosted applications, the user must authenticate as a privileged user to the Administrator Console before being presented with management functionality.  This prevents non-privileged users from having visibility to functions not available to the user.  By limiting visibility, a compromised non-privileged account does not offer information to the attacker to functionality and information needed to further the attack on the application server.

By hosting the Administrator Console on a management-only network, the console is protected from hosted application users, is isolated to only management devices, is not vulnerable to accidental discovery, and most management networks encrypt all traffic protecting management data from accidental disclosure.'
  desc 'check', "Access the Administrator Console through a browser making note of the IP address that is used to access the console.  Review the site's network diagram to validate that the IP used is on a management network and is separate from the public network.

If the Administrator Console is not part of a management network, this is a finding."
  desc 'fix', 'Host the ColdFusion Administrator Console on a management network.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62463'
  tag rid: 'SV-76953r1_rule'
  tag stig_id: 'CF11-05-000161'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-68383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
