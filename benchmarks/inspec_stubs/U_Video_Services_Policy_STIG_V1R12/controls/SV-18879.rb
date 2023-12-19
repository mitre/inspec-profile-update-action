control 'SV-18879' do
  title 'VTC systems and devices must run the latest DoD-approved patches/firmware/software from the system/device vendor.'
  desc 'Some of today’s VTUs do not appropriately protect their passwords or access codes. Best practice and DoD policy dictates that authenticators are to be protected. This includes user account names, passwords, PINs, access codes, etc. The primary method used to protect these bits of information is encryption in transit for both the username and the password, and encryption of passwords in storage. It has been found that some VTC endpoint vendors do not provide this protection for passwords in storage, or at least, have not in the past.

The first such vulnerability to be aware of is one where the administrator password can be obtained across the network by requesting certain files from the CODEC using a web browser. Once the file is accessed, the admin password is displayed in the clear within the source code for the page.

The second such vulnerability to be aware of is one where, in one vendor’s product line, the user access codes are stored in a clear text file that is uploaded to the CODEC. This file is accessible from the FTP server on the CODEC. Access is, however, protected by the remote access password. One can only assume the vendor does not value these access codes as an IA measure since the discussion of their use relates to call accounting.

Vulnerabilities like these and other issues are typically addressed by vendors like most issues are addressed, via patches to software, firmware upgrades, and major new releases of code. As such, it is good practice and a widely used DoD requirement that DoD systems should be running the latest version of software and install all patches to mitigate IA issues. Such is the purpose of the DoD IAVM program.'
  desc 'check', 'Interview the ISSO and validate compliance with the following requirement: 

Ensure all VTC systems and devices are running the latest DoD-approved patches, firmware, and software from the VTC system and device vendors to ensure the most current IA vulnerability mitigations or fixes are employed. Validate the latest software, firmware, and patches are installed on VTC systems and devices. Inspect the documentation regarding DoD testing and approval of the installed versions. If a CODEC or other VTC device is not using the latest software, firmware, and patches from the VTC system or device vendor, this is a finding.

Note: Updating firmware or software to provide desired functionality is preferred. A vendor may provide security updates and patches that offer additional functions. In many cases, the IA Vulnerability Management (IAVM) system mandates updating software to reduce risk to DoD networks.'
  desc 'fix', 'Perform the following tasks: 
Ensure updates to software firmware are patched, tested, and approved by a DoD entity prior to installation of such updates and patches per DoD policy.

Install the latest DoD-approved patches, firmware, and software from the system/device vendor.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18975r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17705'
  tag rid: 'SV-18879r2_rule'
  tag stig_id: 'RTS-VTC 3320.00'
  tag gtitle: 'RTS-VTC 3320'
  tag fix_id: 'F-17602r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECND-1, ECND-2, VIVM-1'
end
