control 'SV-258434' do
  title 'Google Android 14 must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise work profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review that managed Google Android 14 is configured as Corporate Owned Work Managed.
 
This procedure is performed on both the EMM Administrator console and the managed Google Android 14 device. 
 
On the EMM console, configure the default enrollment as Corporate Owned and select "Use for Work & Personal".
 
On the managed Google Android 14 device: 

1. Go to the application drawer.
2. Ensure a Personal tab and a Work tab are present.

If on the EMM console the account the default enrollment is set to Corporate Owned Work Managed or on the managed Android 14 device the user does not have a Work tab, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device as corporate owned with a work profile.

On the EMM console, configure the default enrollment as Corporate Owned, and select "Use for Work & Personal".

Refer to the EMM documentation to determine how to configure the device.'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62175r928325_chk'
  tag severity: 'medium'
  tag gid: 'V-258434'
  tag rid: 'SV-258434r928327_rule'
  tag stig_id: 'GOOG-14-010300'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62099r928326_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
