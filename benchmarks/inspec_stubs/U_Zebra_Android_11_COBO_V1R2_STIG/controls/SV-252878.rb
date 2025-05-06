control 'SV-252878' do
  title 'Zebra Android 11 devices must have the latest available Zebra Android 11 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm the Zebra Android device has the most recently released version of Zebra Android 11 installed. 
 
This procedure is performed on both the EMM console and the Zebra Android 11 device.
 
In the EMM management console, review the version of Zebra Android 11 installed on a sample of managed devices. This procedure will vary depending on the EMM product. 
 
On the Zebra Android 11 device, to see the installed operating system version: 
1. Open "Settings". 
2. Tap "About phone". 
3. Verify "Build number". 
 
If the installed version of the Android operating system on any reviewed Zebra devices is not the latest released by Zebra, this is a finding.'
  desc 'fix', 'Install the latest released version of the Zebra Android 11 operating system on all managed Zebra devices.
 
Note: Zebra Android device operating system updates are released directly by Zebra or can be distributed via the EMM.'
  impact 0.7
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56334r820559_chk'
  tag severity: 'high'
  tag gid: 'V-252878'
  tag rid: 'SV-252878r820561_rule'
  tag stig_id: 'ZEBR-11-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-56284r820560_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
