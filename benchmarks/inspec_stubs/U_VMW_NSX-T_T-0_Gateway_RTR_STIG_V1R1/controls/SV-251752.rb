control 'SV-251752' do
  title 'The NSX-T Tier-0 Gateway must be configured to use a unique key for each autonomous system (AS) with which it peers.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'If the Tier-0 Gateway is not using BGP, this is Not Applicable.

Since the NSX-T Tier-0 Gateway does not reveal the current password, interview the router administrator to determine if unique keys are being used.

If unique keys are not being used for each AS, this is a finding.'
  desc 'fix', 'To set authentication for BGP neighbors do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, and then select "Edit" on the target BGP Neighbor.

Under Timers & Password, enter a password up to 20 characters that is different from other autonomous systems, and then click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55189r810138_chk'
  tag severity: 'medium'
  tag gid: 'V-251752'
  tag rid: 'SV-251752r810140_rule'
  tag stig_id: 'T0RT-3X-000055'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-55143r810139_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
