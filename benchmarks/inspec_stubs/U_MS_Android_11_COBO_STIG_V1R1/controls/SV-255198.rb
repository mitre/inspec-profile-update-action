control 'SV-255198' do
  title 'Microsoft Android 11 devices must have the latest available Microsoft Android 11 operating system installed.'
  desc 'Required security features are not available in earlier operating system versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the Microsoft Android device recently released version of Microsoft Android 11 is installed. 
 
This procedure is performed on both the EMM console and the Microsoft Android 11 device.
 
In the EMM management console, review the version of Microsoft Android 11 installed on a sample of managed devices. This procedure will vary depending on the EMM product. 
 
On the Microsoft Android 11 device, to determine the installed operating system version: 
1. Open "Settings". 
2. Tap "About phone". 
3. Verify "Build number". 
 
If the installed version of the Android operating system on any reviewed Microsoft devices is not the latest released by Microsoft, this is a finding. 

Microsoft Android 11 versions are located here: https://support.microsoft.com/en-us/surface/surface-duo-2-update-history-a3e72e49-8165-4ea6-b490-7fdc2a76c262.'
  desc 'fix', 'Install the latest released version of the Microsoft Android 11 operating system on all managed Microsoft devices.
 
Note: Microsoft Android 11 versions are located here: https://support.microsoft.com/en-us/surface/surface-duo-2-update-history-a3e72e49-8165-4ea6-b490-7fdc2a76c262.'
  impact 0.7
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58811r870800_chk'
  tag severity: 'high'
  tag gid: 'V-255198'
  tag rid: 'SV-255198r870801_rule'
  tag stig_id: 'MSFT-11-010800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58755r869456_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
