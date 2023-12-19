control 'SV-258496' do
  title 'Android 13 devices must be configured to disable the use of third-party keyboards (work profile only).'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the managed Google Android 13 configuration settings to confirm that no third-party keyboards are enabled (work profile only). 
 
This procedure is performed on the EMM console.
 
On the EMM console:

1. Open "Input methods".
2. Tap "Set input methods".
3. Verify only the approved keyboards are selected.

If unapproved third-party keyboards are allowed in the work profile, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disallow the use of third-party keyboards (work profile only). 
 
On the EMM console:

1. Open "Input methods".
2. Tap "Set input methods".
3. Select only the approved keyboards.

Additionally, admins can configure application allowlists for Google Play so no third-party keyboards are available for user installation.'
  impact 0.3
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62236r929302_chk'
  tag severity: 'low'
  tag gid: 'V-258496'
  tag rid: 'SV-258496r929304_rule'
  tag stig_id: 'GOOG-13-710900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62145r929303_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
