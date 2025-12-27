control 'SV-221707' do
  title 'The Oracle Linux operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Note: Per OPORD 16-0080, the preferred intrusion detection system is McAfee Host Intrusion Prevention System (HIPS) in conjunction with SELinux. McAfee Endpoint Security for Linux (ENSL) is an approved alternative to McAfee Virus Scan Enterprise (VSE) and HIPS. For Oracle Linux 7 systems, SELinux is an approved alternative to McAfee HIPS. Regardless of whether or not McAfee HIPS or ENSL is installed, SELinux is interoperable with both McAfee products and SELinux is still required.

Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Get a list of authorized users (other than System Administrator and guest accounts) for the system.

Check the list against the system by using the following command:

# semanage login -l | more
Login Name SELinux User MLS/MCS Range Service
__default__ user_u s0-s0:c0.c1023 *
root unconfined_u s0-s0:c0.c1023 *
system_u system_u s0-s0:c0.c1023 *
joe staff_u s0-s0:c0.c1023 *

All administrators must be mapped to the "sysadm_u", "staff_u", or an appropriately tailored confined role as defined by the organization.

All authorized non-administrative users must be mapped to the "user_u" role.

If they are not mapped in this way, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Use the following command to map a new user to the "sysadm_u" role: 

#semanage login -a -s sysadm_u <username>

Use the following command to map an existing user to the "sysadm_u" role:

#semanage login -m -s sysadm_u <username>

Use the following command to map a new user to the "staff_u" role:

#semanage login -a -s staff_u <username>

Use the following command to map an existing user to the "staff_u" role:

#semanage login -m -s staff_u <username>

Use the following command to map a new user to the "user_u" role:

# semanage login -a -s user_u <username>

Use the following command to map an existing user to the "user_u" role:

# semanage login -m -s user_u <username>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36270r602404_chk'
  tag severity: 'medium'
  tag gid: 'V-221707'
  tag rid: 'SV-221707r603260_rule'
  tag stig_id: 'OL07-00-020020'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-36234r602405_fix'
  tag 'documentable'
  tag legacy: ['V-99153', 'SV-108257']
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
