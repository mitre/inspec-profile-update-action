control 'SV-84725' do
  title 'Windows 10 Mobile whitelist must not include applications with the following characteristics:

- back up MD data to non-DoD cloud servers (including user and application access to cloud backup services, i.e. OneDrive, Box, Dropbox, Google Drive, Amazon Cloud Drive, Azure);
- transmit MD diagnostic data to non-DoD servers;
- voice assistant application if available when MD is locked;
- voice dialing application if available when MD is locked;
- allows synchronization of data or applications between devices associated with user;
- payment processing; and
- allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

SFR ID: FMT_SMF_EXT.1.1 #10b'
  desc 'check', "Review Windows 10 Mobile configuration settings to determine if the mobile device has an application whitelist configured. If feasible, use a spare device to determine if an application whitelist is configured. Verify the application white list does not include applications with the following characteristics:

-back up MD data to non-DoD cloud servers (including user and application access to cloud backup services, i.e. OneDrive, Box, Dropbox, Google Drive, Amazon Cloud Drive, Azure);
-transmit MD diagnostic data to non-DoD servers;
-voice assistant application if available when MD is locked;
-voice dialing application if available when MD is locked;
-allows synchronization of data or applications between devices associated with user;
-payment processing; and
-allows unencrypted (or encrypted but not FIPS 140-2 validated) data sharing with other MDs or printers. 

This validation procedure is only performed on the MDM administration console.

On the MDM administration console:

1. Display policy area for managing allowed applications.
2. Verify a policy exists that creates an application whitelist of allowed applications.
3. Verify no applications are on the whitelist with the prohibited characteristics.
4. Verify the application whitelist policy has been deployed to the target devices under management on the MDM console.

Note: This list can be empty if no applications have been approved. See the STIG supplemental document for additional information.

If the application whitelist policy doesn't exist or doesn't exclude applications with prohibited characteristics or hasn't been deployed to targeted devices under enrollment, this is a finding."
  desc 'fix', 'Configure the MDM system to setup an application whitelist of authorized apps that do not have prohibited characteristics. 

Deploy the policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70103'
  tag rid: 'SV-84725r1_rule'
  tag stig_id: 'MSWM-10-202412'
  tag gtitle: 'PP-MDF-201026'
  tag fix_id: 'F-76339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
