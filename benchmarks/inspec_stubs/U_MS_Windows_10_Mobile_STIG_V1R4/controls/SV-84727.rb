control 'SV-84727' do
  title 'Windows 10 Mobile must be configured to disable VPN split-tunneling (if the MD provides a configurable control for FDP_IFC_EXT.1.1).'
  desc 'Spilt-tunneling allows multiple simultaneous remote connections to the mobile device. Without VPN split-tunneling disabled, malicious applications can covertly off-load device data to a third-party server or set up a trusted tunnel between a non-DoD third-party server and a DoD network, providing a vector to attack the network.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review Windows 10 Mobile documentation and inspect the configuration on Windows 10 Mobile to disable VPN split-tunneling (if Windows 10 Mobile) provides a configurable control). 

This validation procedure is performed only on the MDM administration console. 

On the MDM administration console:

Ask the MDM administrator to verify that the site-specific VPN policy on the MDM console has been configured to disable split-tunneling.

If the site-specific VPN profile on the MDM is not configured to disable split-tunneling functionality, this is a finding.'
  desc 'fix', 'Configure the site-specific VPN profile on the MDM to disable split-tunneling.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70105'
  tag rid: 'SV-84727r1_rule'
  tag stig_id: 'MSWM-10-202418'
  tag gtitle: 'PP-MDF-201029'
  tag fix_id: 'F-76341r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002824']
  tag nist: ['CM-6 b', 'SI-16']
end
