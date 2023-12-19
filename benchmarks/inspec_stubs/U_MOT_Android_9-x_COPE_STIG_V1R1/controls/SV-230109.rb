control 'SV-230109' do
  title 'Motorola Android Pie devices must have a NIAP-validated Motorola Android Pie operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that version LEXL11 NIAP-approved build number (based on Android OS 9.0) is PIE.L11_P_R30.21.10 and Kernel version is 4.4.153. See: https://www.niap-ccevs.org/Product/Compliant.cfm?PID=11002
 
This procedure is performed on both the MDM console and the Motorola Android Pie device. 
 
In the MDM management console, review the version of Motorola Android Pie installed on a sample of managed devices. 
 
On the Android Pie device, to see the installed operating system version: 
1. Open Settings. 
2. Tap "About phone". 
3. Verify "Build number". 
 
If the installed version of the Android operating system on any reviewed Motorola device is not the latest released by the wireless carrier, this is a finding. 

See Motorola's Android operating system patch website: https://source.android.com/security/bulletin/ 
 
If the installed version of the Android Pie operating system is not the NIAP-approved version, this is a finding.)
  desc 'fix', "Install the latest released version of the Motorola Android Pie operating system on all managed Motorola devices. 

For Motorola Android Pie, LEXL11 NIAP-approved build number (based on Android OS 9.0) is PIE.L11_P_R30.21.10, and Kernel version is 4.4.153. See: https://www.niap-ccevs.org/Product/Compliant.cfm?PID=11002

LEX L11 current version: PIE.L11_P_30.22.01 is based on the LEX L11 NIAP version, with small additions. The changes are dedicated to support Verizon Wireless and AT&T carriers' requirements only."
  impact 0.7
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32424r538323_chk'
  tag severity: 'high'
  tag gid: 'V-230109'
  tag rid: 'SV-230109r569708_rule'
  tag stig_id: 'MOTO-09-010900'
  tag gtitle: 'GOOG-09-010900'
  tag fix_id: 'F-32402r538324_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
