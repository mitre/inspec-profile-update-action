control 'SV-255235' do
  title 'Microsoft Android 11 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that no third-party keyboards are enabled. 
 
This procedure is performed on the EMM console.
 
On the EMM console, verify the application allow list for Google Play does not have any third-party keyboards. 

If third-party keyboards are installed, this is a finding.'
  desc 'fix', 'Configure Microsoft Android 11 device to disallow the use of third-party keyboards. 
 
On the EMM console, configure an application allow list for Google Play that does not have any third-party keyboards.'
  impact 0.3
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58848r869320_chk'
  tag severity: 'low'
  tag gid: 'V-255235'
  tag rid: 'SV-255235r870845_rule'
  tag stig_id: 'MSFT-11-011000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58792r869321_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
