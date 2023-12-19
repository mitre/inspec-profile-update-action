control 'SV-217264' do
  title 'All networked SUSE operating systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Note: If the system is not networked this requirement is Not Applicable.

Verify that the SUSE operating system implements SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.

Check that the OpenSSH package is installed on the SUSE operating system with the following command:

# zypper se openssh

S | Name                  | Summary                                                                     | Type
--+---------------- --+------------------------------------------------------+--------
i | openssh              | Secure Shell Client and Server (Remote L-> | package

If the OpenSSH package is not installed, this is a finding.

Check that the OpenSSH service active on the SUSE operating system with the following command:

# systemctl status sshd.service | grep -i "active:"

Active: active (running) since Thu 2017-01-12 15:03:38 UTC; 1 months 4 days ago

If OpenSSH service is not active, this is a finding.'
  desc 'fix', 'Note: If the system is not networked this requirement is Not Applicable.

Configure the SUSE operating system to implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.

Install the OpenSSH package on the SUSE operating system with the following command:

# sudo zypper in openssh

Enable the OpenSSH service to start automatically on reboot with the following command:

# sudo systemctl enable sshd.service

For the changes to take effect immediately, start the service with the following command:

# sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18492r369948_chk'
  tag severity: 'high'
  tag gid: 'V-217264'
  tag rid: 'SV-217264r603262_rule'
  tag stig_id: 'SLES-12-030100'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-18490r369949_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag legacy: ['SV-92137', 'V-77441']
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
