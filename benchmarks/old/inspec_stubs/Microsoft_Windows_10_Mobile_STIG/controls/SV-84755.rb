control 'SV-84755' do
  title 'Windows 10 Mobile must be configured to implement the management setting: 

Disable the ability to copy and paste data between trusted and non-trusted applications and between trusted and non-trusted networks.'
  desc 'Copy/Paste data protection provides the capability to restrict transfer of data between managed (work/enterprise) and non-managed (personal) apps. Sensitive DoD data could be compromised if this feature is not disabled as data leakage can occur.

Note: The Windows Information Protection configuration control policy implements the following individual controls:  
Network address space including:
* IP address ranges
* Domain name spaces to be protected
* Control of copy and paste between apps and between DoD and non-DoD networks

These may be configured separately on the MDM server as part of a single Data Protection policy.

SFR ID: FMT_SMF_EXT.1.1 #42'
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if the mobile device is enforcing the policy to prevent the use of copy and paste between applications and from trusted networks. If feasible, use a spare device to test if copy and paste is disabled.
This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.   
On the MDM Administration Console:
Check whether these settings are configured: 
Ask the MDM administrator to verify the "enterprise data protection" security policy was set to be enforced for Windows 10 Mobile devices.
1. Verify that a list of Windows Store applications that should be managed is configured.   
NOTE:  This validation assumes that Microsoft Office Mobile applications such as Word are configured under the MDM policy to be a managed application as Word will be used in the mobile device validation of copy/paste protection.
2. Verify the policy defines "Enterprise IP Ranges" that list IPv4 and/or IPv6 address ranges for protected DoD network space.
3. Verify that "Enterprise Protected Domain Names" for the primary DoD networks (i.e., dod.mil, disa.mil) and additional domain space such as email domains (i.e., mail.mil) are defined.
4. Verify that the "Enterprise Network Domain Names" setting includes the (comma-separated list of domains that computers use within your enterprise (i.e. contoso.sharepoint.com, fabrikam.com) is defined.
5. Verify the "Protection Mode" for your enterprise data (paste/drop/share) policy is set to "Block" pasting/copying data to non-trusted DoD network locations.
6. Verify the "Revoke encryption keys on unenroll" setting is enforced (if available) to prevent encryption from being removed from files after MDM unenrollment.
7. Verify the "Protection Under Lock" policy is enforced.
8. Verify the setting to show Windows Information Protection icons on encrypted files in File Manager is set to "on/true". This is not mandatory but is a desirable setting.

On the Windows 10 Mobile device:
1. Open an existing encrypted Word document on a Windows 10 Mobile phone, open one from a DoD network location, or create a new Word document. Then, using the menu, tap "Save" and then tap "Save a copy of this file" to save that document and encrypt it.

2. Either type new text or tap and select existing text in the document and then when selected, tap the Clipboard icon in the pop-up toolbar to copy selected text to the clipboard.

3. Go to the "All apps" page. From the Start page, swipe left to reveal.

4. Scroll down to or search for the "Get Started" app, then tap to launch.

5. Tap on the Search icon at the upper right. Tap into the text box. The keyboard will pop up and there will be a small toolbar above it with an icon for the Clipboard at the far left.

6. Verify that when tapping on the Paste icon in the toolbar that the message "This is work content only. Your organization <domain name in policy>, doesn't allow you to change ownership of this content from work to personal" appears and text is blocked from being copied.

If the MDM does not enforce the appropriate polices listed for controlling "enterprise data protection" or if on the phone, text can be copied from a managed application containing an encrypted document and pasted into an untrusted/managed app, this is a finding.)
  desc 'fix', 'Configure the MDM system with a security policy that requires the "enterprise data protection” capability to be enforced for Windows 10 Mobile devices. 

Within the policy:
1. Select which applications are considered managed. These applications are allowed to access DoD data from approved network sources.
2. Configure IP address ranges and domain names for DoD network space.
3. Configure protection policy to block Copy and Paste operations.

Refer to MICROSOFT WINDOWS 10 MOBILE SUPPLEMENTAL PROCEDURES, Section 2.2, for implementation details.

Deploy the MDM policy to managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70609r4_chk'
  tag severity: 'low'
  tag gid: 'V-70133'
  tag rid: 'SV-84755r3_rule'
  tag stig_id: 'MSWM-10-911101'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76369r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
