control 'SV-250572' do
  title 'The system must enforce the entire password during authentication.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', 'Disable lock down mode.

Enable the ESXi Shell and attempt to log into the root account using only the first 8 of 14 required characters.

If the login succeeds, this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the host and verify the expected settings are configured in the  /etc/pam.d/passwd file. The entry format is "password requisite /lib/security/pam_passwdqc.so similar=deny retry=N min=N0,N1,N2,N3,N4". The "N4" field controls the behavior requiring at least one character each of the 4 different character classes, with a minimum required length of 14 characters.

# vi /etc/pam.d/passwd

Set the "N4" password complexity field to "14" and set  the "N0" thru "N3" fields to "disabled".

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54007r798713_chk'
  tag severity: 'medium'
  tag gid: 'V-250572'
  tag rid: 'SV-250572r798715_rule'
  tag stig_id: 'GEN000585-ESXI5-000080'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53961r798714_fix'
  tag 'documentable'
  tag legacy: ['SV-51079', 'V-39263']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
