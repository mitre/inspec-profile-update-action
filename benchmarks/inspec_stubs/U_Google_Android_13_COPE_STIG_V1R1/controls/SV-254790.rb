control 'SV-254790' do
  title 'Google Android 13 must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise work profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review that managed Google Android 13 is configured as Corporate Owned Work Managed.
 
This procedure is performed on both the EMM Administrator console and the managed Google Android 13 device. 
 
On the EMM console, configure the default enrollment as Corporate Owned and select "Use for Work & Personal".
 
On the managed Google Android 13 device: 

1. Go to the application drawer.
2. Ensure a Personal tab and a Work tab are present.

If on the EMM console the account the default enrollment is set to Corporate Owned Work Managed or on the managed Android 13 device the user does not have a Work tab, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device as corporate owned with a work profile.

On the EMM console, configure the default enrollment as Corporate Owned, and select "Use for Work & Personal".

Refer to the EMM documentation to determine how to configure the device.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58401r862750_chk'
  tag severity: 'medium'
  tag gid: 'V-254790'
  tag rid: 'SV-254790r862752_rule'
  tag stig_id: 'GOOG-13-010300'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58347r862751_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
