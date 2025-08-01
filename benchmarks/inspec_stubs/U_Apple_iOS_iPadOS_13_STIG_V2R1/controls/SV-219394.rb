control 'SV-219394' do
  title 'The Apple iOS/iPadOS must be Supervised by the MDM.'
  desc 'When an iOS/iPadOS is not supervised, the DoD mobile service provider cannot control when new iOS/iPadOS updates are installed on site managed devices. Most updates should be installed immediately to mitigate new security vulnerabilities, while some sites need to test each update prior to installation to insure critical missions are not adversely impacted by the update.

Also, several password and data protection controls can only be implemented when an Apple device is Supervised.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm site managed iOS/iPadOS devices are supervised.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify all managed Apple devices are supervised (verification procedure will vary by MDM product).

Note: if the Apple device is not managed by an MDM and supervision is set up via Apple Configurator, this procedure is not applicable.

On the iPhone and iPad:
1. Open the Settings app.
2. Verify a message similar to the following appears on the screen: "This iPad is supervised by (name of site DoD mobile service provider)." 

If site managed iOS/iPadOS devices are not supervised, this is a finding.'
  desc 'fix', "Use one of the following methods to Supervise iOS and iPadOS devices managed by the DoD mobile service provider.

Method 1:
-Register all current and new iOS and iPadOS devices in the DoD mobile service provider's Device Enrollment Program (DEP)/Apple Business Manager (ABM) account.
-Enable Supervision of managed iOS/iPadOS devices in the MDM.

Method 2: 
-Configure each iOS/iPadOS device using the Apple Configurator tool for Supervision. This method is usually only appropriate when MDM management of the DoD Apple device is not appropriate or an older device cannot be registered in DEP/ABM."
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21119r547693_chk'
  tag severity: 'medium'
  tag gid: 'V-219394'
  tag rid: 'SV-219394r604137_rule'
  tag stig_id: 'AIOS-13-013700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21118r547703_fix'
  tag 'documentable'
  tag legacy: ['SV-106621', 'V-97517']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000097']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AC-20 (2)']
end
