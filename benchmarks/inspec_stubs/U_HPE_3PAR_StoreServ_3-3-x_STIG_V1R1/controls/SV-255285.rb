control 'SV-255285' do
  title 'The HPE 3PAR OS must be configured to implement NIST FIPS-validated cryptography for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government, since this provides assurance they have been tested and validated.

The HPE 3PAR OS can be configured to use FIPS validated cryptographic methods for communications secrecy. It also has an encryption license feature that controls the handling of Self-Encrypting backend drives, which requires an authorized service provider for install and activation.

'
  desc 'check', 'Verify the status of the FIPS communication library:

cli% controlsecurity fips status

If the line "FIPS Mode:" is not "Enabled", this is a finding.

If any of the service lines for CLI, EKM, LDAP, SNMP, SSH, or SYSLOG are Disabled, this is a finding.

If CIM, VASA, or WSAPI are "Disabled", and the mission requires any of these services, this is a finding.

Review the requirements by the Information Owner to determine if the system will store sensitive or classified information.

If the mission does not store sensitive, or classified information, the remainder of the check is not applicable.

If the mission stores classified data, check the status of backend drive encryption:

cli% controlencryption status

If Licensed, Enabled, or BackupSaved are "no", or the keystore is not EKM, this is a finding.'
  desc 'fix', 'Set the communications encryption module into fips mode:

cli% controlsecurity fips enable

If the mission stores classified information, contact an authorized service provider to install and configure the licensed encryption feature.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58958r870172_chk'
  tag severity: 'medium'
  tag gid: 'V-255285'
  tag rid: 'SV-255285r870174_rule'
  tag stig_id: 'HP3P-33-002069'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-58902r870173_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
