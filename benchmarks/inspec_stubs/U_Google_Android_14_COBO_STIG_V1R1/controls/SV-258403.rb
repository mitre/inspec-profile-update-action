control 'SV-258403' do
  title 'Android 14 devices must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the managed Google Android 14 configuration settings to confirm that no third-party keyboards are enabled. 
 
This procedure is performed on the EMM console.
 
On the EMM console:

COBO and COPE:

1. Open "Input methods".
2. Tap "Set input methods".
3. Verify only the approved keyboards are selected.

If third-party keyboards are allowed, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to disallow the use of third-party keyboards. 
 
On the EMM console:

COBO and COPE:

1. Open "Input methods".
2. Tap "Set input methods".
3. Select only the approved keyboard.

Additionally, Admins can configure application allowlists for Google Play that do not have any third-party keyboards for user installation.'
  impact 0.3
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62144r928232_chk'
  tag severity: 'low'
  tag gid: 'V-258403'
  tag rid: 'SV-258403r928234_rule'
  tag stig_id: 'GOOG-14-010900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62068r928233_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
