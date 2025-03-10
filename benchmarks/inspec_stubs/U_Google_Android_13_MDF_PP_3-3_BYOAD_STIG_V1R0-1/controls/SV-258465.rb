control 'SV-258465' do
  title 'The EMM detection/monitoring system must use continuous monitoring of enrolled Google Android 13 BYOAD.'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and the work profile can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure. Continuous monitoring must be used to ensure all noncompliance events will be seen by the detection system.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(3)iii).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM detection/monitoring system is configured to use continuous monitoring of enrolled Google Android 13 BYOAD. The exact procedure will depend on the EMM system used at the site.

If the EMM detection/monitoring system is not configured to use continuous monitoring of enrolled Google Android 13 BYOAD, this is a finding.'
  desc 'fix', 'Configure the EMM detection/monitoring system to use continuous monitoring of enrolled Google Android 13 BYOAD. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62205r929209_chk'
  tag severity: 'medium'
  tag gid: 'V-258465'
  tag rid: 'SV-258465r929211_rule'
  tag stig_id: 'GOOG-13-800700'
  tag gtitle: 'PP-BYO-000070'
  tag fix_id: 'F-62114r929210_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
