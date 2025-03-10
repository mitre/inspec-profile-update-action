control 'SV-237818' do
  title 'DoD-approved encryption must be implemented to protect the confidentiality and integrity of remote access sessions, information during preparation for transmission, information during reception, and information during transmission in addition to enforcing replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

Facilitating the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.

'
  desc 'check', 'Verify that insecure ports are disabled.

cli% setnet disableports yes

Confirm the operation by entering "y" and pressing "Enter".

If an error is reported, this is a finding.

If available, a remote port scan can also verify that only secure ports are open. From a command shell on a Linux workstation in the operational environment, enter the following command:

cli% nmap -sT -sU -sV --version-all -vv -p1 -65535 <ip address of storage system> 

If any port other than 22 (ssh), 123 (ntp), 161 and 162 (snmp), and 5783 (ssl manageability) report as open, this is a finding.'
  desc 'fix', 'Disable insecure ports via this command by entering the following command:

cli% setnet disableports yes

Confirm the operation by entering "y" and pressing "Enter".'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41028r647861_chk'
  tag severity: 'high'
  tag gid: 'V-237818'
  tag rid: 'SV-237818r647863_rule'
  tag stig_id: 'HP3P-32-001100'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-40987r647862_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000096-GPOS-00050', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000297-GPOS-00115', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-85111', 'V-70489']
  tag cci: ['CCI-000068', 'CCI-000366', 'CCI-000382', 'CCI-000803', 'CCI-001453', 'CCI-001941', 'CCI-002314', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'CM-6 b', 'CM-7 b', 'IA-7', 'AC-17 (2)', 'IA-2 (8)', 'AC-17 (1)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
