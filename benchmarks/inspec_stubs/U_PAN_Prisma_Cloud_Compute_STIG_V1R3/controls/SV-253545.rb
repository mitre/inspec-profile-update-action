control 'SV-253545' do
  title 'Prisma Cloud Compute Defender must reestablish communication to the Console via mutual TLS v1.2 WebSocket session.'
  desc 'When the secure WebSocket session between the Prisma Cloud Compute Console and Defenders is disconnected, the Defender will continually attempt to reestablish the session. Without reauthentication, unidentified or unknown devices may be introduced; thereby facilitating malicious activity.

The Console must be configured to remove a Defender that has not established a connection in a specified period of days.'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Defenders.
 
Select the "Manage" tab. Select the "Defenders" tab.

Click "Advanced Settings".

If "Automatically remove disconnected Defenders after (days)" is not configured to the organization's policies, this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute's Manage >> Defenders. 

Select the "Manage" tab. Select the "Defenders" tab.

Click "Advanced Settings".

Set the "Automatically remove disconnected Defenders after (days)" value to the organization's defined period.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56997r840471_chk'
  tag severity: 'medium'
  tag gid: 'V-253545'
  tag rid: 'SV-253545r879763_rule'
  tag stig_id: 'CNTR-PC-001250'
  tag gtitle: 'SRG-APP-000390-CTR-000930'
  tag fix_id: 'F-56948r840472_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
