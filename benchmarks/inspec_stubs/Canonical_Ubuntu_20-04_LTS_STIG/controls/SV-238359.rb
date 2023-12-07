control 'SV-238359' do
  title "The Ubuntu operating system's Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization."
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor. 
 
Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization. 
 
Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify that APT is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization. 
 
Check that the "AllowUnauthenticated" variable is not set at all or is set to "false" with the following command: 
 
$ grep AllowUnauthenticated /etc/apt/apt.conf.d/* 
/etc/apt/apt.conf.d/01-vendor-Ubuntu:APT::Get::AllowUnauthenticated "false"; 
 
If any of the files returned from the command with "AllowUnauthenticated" are set to "true", this is a finding.'
  desc 'fix', 'Configure APT to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization. 
 
Remove/update any APT configuration files that contain the variable "AllowUnauthenticated" to "false", or remove "AllowUnauthenticated" entirely from each file. Below is an example of setting the "AllowUnauthenticated" variable to "false": 
 
APT::Get::AllowUnauthenticated "false";'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41569r654250_chk'
  tag severity: 'medium'
  tag gid: 'V-238359'
  tag rid: 'SV-238359r853434_rule'
  tag stig_id: 'UBTU-20-010438'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-41528r654251_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
