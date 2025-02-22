control 'SV-80193' do
  title 'BlackBerry OS 10.3 work space whitelist must not include applications with the following characteristics: (See Vulnerability Discussion for list).'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

List of characteristics:
-backup MD data to non-DoD cloud servers (including user and application access to cloud backup services);
-transmit MD diagnostic data to non-DoD servers;
-voice assistant application if available when MD is locked;
-voice dialing application if available when MD is locked;
-allows synchronization of data or applications between devices associated with user;
-payment processing; and
-allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

SFR ID: FMT_SMF_EXT.1.1 #10b'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry contains applications with the following characteristics:
-backup MD data to non-DoD cloud servers (including user and application access to cloud backup services);
-transmit MD diagnostic data to non-DoD servers;
-voice assistant application if available when MD is locked;
-voice dialing application if available when MD is locked;
-allows synchronization of data or applications between devices associated with user;
-payment processing; and
-allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "APPS” tab at the top of the screen.
2. Scroll through the list of applications.
3. Verify that there are no applications installed with the following Characteristics:
-backup MD data to non-DoD cloud servers (including user and application access to cloud backup services);
-transmit MD diagnostic data to non-DoD servers;
-voice assistant application if available when MD is locked;
-voice dialing application if available when MD is locked;
-allows synchronization of data or applications between devices associated with user;
-payment processing; and
-allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

On the BlackBerry device: 
1. From the Work Space and Personal Space (on applicable activation types), swipe through the application windows.
2. Verify that there are no applications installed with the following Characteristics:
-backup MD data to non-DoD cloud servers (including user and application access to cloud backup services);
-transmit MD diagnostic data to non-DoD servers;
-voice assistant application if available when MD is locked;
-voice dialing application if available when MD is locked;
-allows synchronization of data or applications between devices associated with user;
-payment processing; and
-allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs, display screens (screen mirroring), or printers.

If on the BES12 console, any applications are listed that contain the prohibited characteristics, or on the BlackBerry device, if any applications containing the prohibited characteristics are installed, this is a finding. 

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "APPS” tab at the top of the screen.
2. Select the check box next to all applications to be removed.
3. Select the trashcan icon in the upper left to delete the selected applications.
4. Select "Delete" when prompted.

On the BlackBerry Device:
1. Select and hold the icon for the application to be deleted until the icons begin to pulse.
2. Select the trashcan icon next to the application to be deleted.
3. Select "Delete" when prompted.
4. Repeat for additional applications to be deleted.
5. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66357r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65703'
  tag rid: 'SV-80193r1_rule'
  tag stig_id: 'BB10-3X-000330'
  tag gtitle: 'PP-MDF-201026'
  tag fix_id: 'F-71745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
