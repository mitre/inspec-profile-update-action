control 'SV-253846' do
  title 'The Tanium Server must be configured to allow only signed content to be imported.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Patches, service packs, or application components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software is from an approved certificate authority (CA).'
  desc 'check', 'Note: This requirement applies only to Tanium implementations in production. If implementation being evaluated is in development, this requirement is not applicable.

1. Access the Tanium Server through interactive logon.

2. Open Windows Explorer and browse to the installation drive of the Tanium Server (e.g., E:\\Program Files\\Tanium\\Tanium Server).

3. Locate the "tanium.license" file and double-click it.

4. Select Notepad to open the "tanium.license" file. 

5. Select "Edit" and then select "Find" from the menu in Notepad.

6. Type "allow_unsigned_import" in the search box and select "Find Next."

If "allow unsigned_import" is followed by ":true", this is a finding.

If "allow unsigned_import" is followed by ":false", this is not a finding.'
  desc 'fix', 'Contact Tanium for a corrected license file.

1. Double-click the new "tanium.license" file and select Notepad to open the file. 

2.. Select "Edit" and then select "Find" from the menu in Notepad.

3. Type "allow_unsigned_import" in the search box and select "Find Next".

4. Verify "allow unsigned_import" is followed by ":false".

5. Access the Tanium Server through interactive logon.

6. Open Windows Explorer and browse to the installation drive of the Tanium Server (e.g., E:\\Program Files\\Tanium\\Tanium Server).

7. Locate the "tanium.license" file and copy it to a backup location.

8. Copy the new "tanium.license" file to the installation drive and directory of the Tanium Server (e.g., E:\\Program Files\\Tanium\\Tanium Server).'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57298r842564_chk'
  tag severity: 'medium'
  tag gid: 'V-253846'
  tag rid: 'SV-253846r850129_rule'
  tag stig_id: 'TANS-SV-000015'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-57249r842565_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
