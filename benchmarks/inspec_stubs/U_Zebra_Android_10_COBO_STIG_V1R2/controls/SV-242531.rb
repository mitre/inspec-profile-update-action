control 'SV-242531' do
  title 'Zebra Android 10 devices must have the latest available Zebra Android 10 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that the most recently released version of Zebra Android 10 is installed. 
 
This procedure is performed on both the MDM Administration Console and the Zebra Android 10 device.
 
On the MDM console, review the version of Zebra Android 10 installed on a sample of managed devices. This procedure will vary depending on the MDM product. 
 
On the Zebra Android 10 device: 
1. Open Settings. 
2. Tap "About phone". 
3. Verify "Build number". 
 
If the installed version of the Android operating system on any reviewed Zebra devices is not the latest released by Zebra, this is a finding. 

Zebra's Android operating system patch website is https://www.zebra.com/us/en/support-downloads/lifeguard-security.html.)
  desc 'fix', 'Install the latest released version of the Zebra Android 10 operating system on all managed Zebra devices.
 
Note: Zebra Android 10 device operating system updates are released directly by Zebra or can be distributed via the MDM.'
  impact 0.7
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45806r714436_chk'
  tag severity: 'high'
  tag gid: 'V-242531'
  tag rid: 'SV-242531r714438_rule'
  tag stig_id: 'ZEBR-10-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45763r714437_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
