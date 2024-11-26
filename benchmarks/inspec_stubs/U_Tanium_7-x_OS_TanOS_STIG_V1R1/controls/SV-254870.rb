control 'SV-254870' do
  title 'The Tanium Operating System (TanOS) must protect against or limit the effects of denial of service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "A" to go to the "Appliance Configuration" menu.

3. Enter "A" to go to the "Security" menu.

4. Enter "X" to go to the "Advanced Security" menu.

5. If you see "DOS protection: disabled" in the middle of the screen, this is a finding.'
  desc 'fix', '1. Sign in to the TanOS console as a user with the tanadmin role.
2. Enter "A" to go to the "Appliance Configuration" menu.

3. Enter "A" to go to the "Security" menu.

4. Enter "X" to go to the "Advanced Security" menu.

5. Enter "6" to enable DoS protection. The screen updates with an enabled status.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58483r866149_chk'
  tag severity: 'medium'
  tag gid: 'V-254870'
  tag rid: 'SV-254870r866151_rule'
  tag stig_id: 'TANS-OS-001420'
  tag gtitle: 'SRG-OS-000420'
  tag fix_id: 'F-58427r866150_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
