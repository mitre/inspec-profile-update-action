control 'SV-258492' do
  title 'Google Android 13 must be provisioned as a BYOAD device (Android work profile for employee-owned devices [BYOD]).'
  desc 'The Android work profile for employee-owned devices (BYOD) is the designated application group for the BYOAD use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review that managed Google Android 13 is configured for BYOD (work profile for employee-owned devices [BYOD]).
 
This procedure is performed on both the EMM Administrator console and the managed Google Android 13 device. 
 
On the EMM console, configure the default enrollment as work profile for employee-owned devices (BYOD).
 
On the managed Google Android 13 device: 

1. Go to the application drawer.
2. Ensure a Personal tab and a Work tab are present.

If on the EMM console, the default enrollment is not set for BYOD (work profile for employee-owned devices [BYOD]), or if on the managed Android 13 device, the user does not have a Work tab, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device for BYOD (work profile for employee-owned devices [BYOD]).

On the EMM console, configure the default enrollment as work profile for employee-owned devices (BYOD).

Refer to the EMM documentation to determine how to configure the device.'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62232r929290_chk'
  tag severity: 'medium'
  tag gid: 'V-258492'
  tag rid: 'SV-258492r929292_rule'
  tag stig_id: 'GOOG-13-710300'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62141r929291_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
