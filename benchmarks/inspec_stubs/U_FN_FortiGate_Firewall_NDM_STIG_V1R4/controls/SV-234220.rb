control 'SV-234220' do
  title 'The FortiGate device must only install patches or updates that are validated by the vendor via digital signature or hash.'
  desc 'Changes to any software components can have significant effects on the overall security of the network device. Verifying software components have been digitally signed or hashed ensures that the software has not been tampered with and has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate or verified with an integrity hash provided by the vendor. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and has been provided by a trusted vendor.'
  desc 'check', 'Verify the process used to apply updates and patches to the system.

If the system is updated via a FortiGuard or FortiManager server, those solutions meet the requirement and this is NOT a finding.

If the system is not using a FortiGuard or FortiManager server, and a process is not defined to manually verify the update hash value with the vendor site, this is a finding.'
  desc 'fix', "Administrators can download software directly from a FortiGuard or FortiManager server. These servers are authenticated using digital certificates that ensure identity and non-repudiation of the source packages. This is a preferred method of applying updates.

 The Administrator can also download the software from Fortinet's support website portal. The website includes a file checksum to verify file integrity prior to uploading.
 
Develop a process to download the update files from the Fortinet website, and manually compare the download hash to the hash value provided on the vendor site before applying the update files to the system."
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37405r611847_chk'
  tag severity: 'medium'
  tag gid: 'V-234220'
  tag rid: 'SV-234220r879584_rule'
  tag stig_id: 'FGFW-ND-000305'
  tag gtitle: 'SRG-APP-000131-NDM-000243'
  tag fix_id: 'F-37370r611848_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
