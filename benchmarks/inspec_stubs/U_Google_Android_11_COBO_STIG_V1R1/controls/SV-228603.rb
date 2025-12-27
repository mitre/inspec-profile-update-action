control 'SV-228603' do
  title 'Google Android 11 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that no third-party keyboards are enabled. 
 
This procedure is performed on the EMM console.
 
On the EMM console, configure application allow list for Google Play that does not have any third-party keyboards. 

If third-party keyboards are allowed, this is a finding.'
  desc 'fix', 'Configure Google Android 11 device to disallow the use of third-party keyboards. 
 
On the EMM console, configure application allow list for Google Play that does not have any third-party keyboards.'
  impact 0.3
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30838r505634_chk'
  tag severity: 'low'
  tag gid: 'V-228603'
  tag rid: 'SV-228603r510289_rule'
  tag stig_id: 'GOOG-11-011000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30815r505635_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
