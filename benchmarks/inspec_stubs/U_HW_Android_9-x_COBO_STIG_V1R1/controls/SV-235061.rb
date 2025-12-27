control 'SV-235061' do
  title 'Honeywell Mobility Edge Android Pie devices must have a NIAP validated Honeywell Mobility Edge Android Pie devices operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that version HON660-P-88.00.12 is installed (it is the NIAP-approved version). NOTE: This version of Android can only be installed on devices purchased directly from Honeywell. 
 
This procedure is performed on both the MDM console and the Honeywell Android Pie device. 
 
In the MDM management console, review the version of Honeywell Android Pie installed on a sample of managed devices. 
 
On the Honeywell Android Pie device, to see the installed operating system version: 
1. Open Settings. 
2. Tap "About phone". 
3. Verify "Build number". 
 
If the installed version of the Android operating system on any reviewed Honeywell device is not the latest released by the wireless carrier, this is a finding. 

Honeywell's Android operating system patch website is available at https://source.android.com/security/bulletin/.
 
If the installed version of the Android Pie operating system is not the NIAP-approved version, this is a finding.)
  desc 'fix', 'Install the latest released version of the Honeywell Android Pie operating system on all managed Honeywell devices. For Honeywell Android Pie devices, version HON660-P-88.00.12 must be installed (it is the NIAP-approved version). NOTE: This version of Android can only be installed on devices purchased directly from Honeywell. 
 
NOTE: In Honeywell Android devices, operating system updates are released by the wireless carrier (for example, Sprint, T-Mobile, Verizon Wireless, and ATT).'
  impact 0.7
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38249r623093_chk'
  tag severity: 'high'
  tag gid: 'V-235061'
  tag rid: 'SV-235061r626530_rule'
  tag stig_id: 'HONW-09-010900'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38212r623094_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
