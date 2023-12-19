control 'SV-255230' do
  title 'Microsoft Android 11 must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise Work Profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review that Microsoft Android 11 is configured as Corporate Owned Work Managed.
 
This procedure is performed on both the EMM Administrator console and the Microsoft Android 11 device. 
 
On the EMM console, configure the default enrollment as Corporate Owned, and select "Use for Work & Personal".
 
On the Microsoft Android 11 device: 
1. Go to the application drawer.
2. Ensure a Personal tab and a Work tab are present.

If on the EMM console the account the default enrollment is set to Corporate Owned Work Managed or on the Microsoft Android 11 device the user does not see a Work tab, this is a finding.'
  desc 'fix', 'Configure Microsoft Android 11 device as corporate owned with a work profile.

On the EMM console, configure the default enrollment as Corporate Owned, and select "Use for Work & Personal".

Refer to the EMM documentation to determine how to configure the device.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58843r870778_chk'
  tag severity: 'medium'
  tag gid: 'V-255230'
  tag rid: 'SV-255230r870779_rule'
  tag stig_id: 'MSFT-11-009600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58787r869306_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
