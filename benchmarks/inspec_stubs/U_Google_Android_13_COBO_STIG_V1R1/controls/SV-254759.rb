control 'SV-254759' do
  title 'Android 13 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the managed Google Android 13 configuration settings to confirm that no third-party keyboards are enabled. 
 
This procedure is performed on the EMM console.
 
On the EMM console:

COBO and COPE:

1. Open "Input methods".
2. Tap "Set input methods".
3. Verify only the approved keyboards are selected.

If third-party keyboards are allowed, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disallow the use of third-party keyboards. 
 
On the EMM console:

COBO and COPE:

1. Open "Input methods".
2. Tap "Set input methods".
3. Select only the approved keyboard.

Additionally, Admins can configure application allowlists for Google Play that do not have any third-party keyboards for user installation.'
  impact 0.3
  ref 'DPMS Target Google Android 13 COBO'
  tag check_id: 'C-58370r862474_chk'
  tag severity: 'low'
  tag gid: 'V-254759'
  tag rid: 'SV-254759r862476_rule'
  tag stig_id: 'GOOG-13-010900'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58316r862475_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
