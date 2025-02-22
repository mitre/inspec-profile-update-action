control 'SV-252879' do
  title 'Zebra Android 11 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that no third-party keyboards are enabled. 
 
This procedure is performed on the EMM console.
 
On the EMM console, configure application allow list for Google Play that does not have any third-party keyboards. 

If third-party keyboards are allowed, this is a finding.'
  desc 'fix', 'Configure Zebra Android 11 device to disallow the use of third-party keyboards. 
 
On the EMM console, configure application allow list for Google Play that does not have any third-party keyboards.'
  impact 0.3
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56335r820562_chk'
  tag severity: 'low'
  tag gid: 'V-252879'
  tag rid: 'SV-252879r820564_rule'
  tag stig_id: 'ZEBR-11-011000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-56285r820563_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
