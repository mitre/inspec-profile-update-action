control 'SV-258686' do
  title "Samsung Android's Work profile must be configured to disable exceptions to the access control policy that prevent application processes and groups of application processes from accessing all data stored by other application processes and groups of application processes."
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DOD sensitive information. To mitigate this risk, there are data sharing restrictions, primarily from sharing data from personal (unmanaged) apps and work (managed) apps. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the Administrator or common application developer mitigates this risk.

Copy/paste of data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the Administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review the Samsung documentation and inspect the configuration to verify the Samsung Android devices are enabling an access control policy that prevents application processes and groups of application processes from accessing all data stored by other application processes and groups of application processes.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the Work profile restrictions, set "Cross profile copy/paste" to "Disallow".

On the Samsung Android device: 
1. Using any Work app, copy text to the clipboard.
2. Using any Personal app, verify the clipboard text cannot be pasted.

If on the management tool "Cross profile copy/paste" is not set to "Disallow", or on the Samsung Android device the clipboard text can be pasted into a Personal app, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enable an access control policy that prevents application processes and groups of application processes from accessing all data stored by other application processes and groups of application processes.

On the management tool, in the Work profile restrictions section, set "Cross profile copy/paste" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62426r931256_chk'
  tag severity: 'medium'
  tag gid: 'V-258686'
  tag rid: 'SV-258686r931258_rule'
  tag stig_id: 'KNOX-14-210250'
  tag gtitle: 'PP-MDF-333280'
  tag fix_id: 'F-62335r931257_fix'
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002530']
  tag nist: ['AC-6 (8)', 'SC-39']
end
