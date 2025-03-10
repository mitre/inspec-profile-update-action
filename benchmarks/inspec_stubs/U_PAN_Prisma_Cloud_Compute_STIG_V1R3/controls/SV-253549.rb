control 'SV-253549' do
  title 'Prisma Cloud Compute must be running the latest release.'
  desc 'Prisma Cloud Compute releases are distributed as Docker images. Each release updates or removes components as needed based on the vulnerabilities associated with the component or the functional need of the component.'
  desc 'check', 'Navigate to the Prisma Cloud Compute Console. 

In the top right corner, click the bell icon. A banner with the version will display. 

If there is a newer version, this is a finding.'
  desc 'fix', 'Upgrade the Prisma Cloud Compute Console and Defenders according to published procedures.

https://docs.twistlock.com/docs/compute_edition/upgrade/upgrade_process_self_hosted.html'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-57001r840483_chk'
  tag severity: 'medium'
  tag gid: 'V-253549'
  tag rid: 'SV-253549r879825_rule'
  tag stig_id: 'CNTR-PC-001440'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag fix_id: 'F-56952r840484_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
