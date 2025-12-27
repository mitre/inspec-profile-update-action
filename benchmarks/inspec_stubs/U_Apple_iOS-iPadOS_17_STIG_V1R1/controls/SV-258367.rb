control 'SV-258367' do
  title 'The Apple iOS/iPadOS 17 must be supervised by the MDM.'
  desc 'When an iOS/iPadOS is not supervised, the DOD mobile service provider cannot control when new iOS/iPadOS updates are installed on site-managed devices. Most updates should be installed immediately to mitigate new security vulnerabilities, while some sites need to test each update prior to installation to ensure critical missions are not adversely impacted by the update.

Several password and data protection controls can be implemented only when an Apple device is supervised.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm site-managed iOS/iPadOS devices are supervised.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify all managed Apple devices are supervised (verification procedure will vary by MDM product).

Note: If the Apple device is not managed by an MDM and supervision is set up via Apple Configurator, this procedure is not applicable.

On the iPhone and iPad:
1. Open the Settings app.
2. Verify a message similar to the following appears on the screen: "This iPad is supervised by (name of site DOD mobile service provider)." 

If site-managed iOS/iPadOS devices are not supervised, this is a finding.'
  desc 'fix', "Use one of the following methods to supervise iOS and iPadOS devices managed by the DOD mobile service provider.

Method 1:
- Register all current and new iOS and iPadOS devices in the DOD mobile service provider's Automated Device Management/Apple Business Manager (ABM) account.
- Enable supervision of managed iOS/iPadOS devices in the MDM.

Method 2: 
- Configure each iOS/iPadOS device using the Apple Configurator tool for Supervision.
- This method is usually only appropriate when MDM management of the DOD Apple device is not appropriate or an older device cannot be registered in ABM."
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62108r927782_chk'
  tag severity: 'medium'
  tag gid: 'V-258367'
  tag rid: 'SV-258367r927784_rule'
  tag stig_id: 'AIOS-17-013200'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62032r927783_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
