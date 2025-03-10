control 'SV-250632' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and verify the expected setting is configured in the /etc/pam.d/passwd file. The entry format will look similar to "password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok shadow". Search for the existing hash key (sha512).

# grep "^password sufficient " /etc/pam.d/passwd | grep sha512

If sha512 is missing from the configuration, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.
As root, log in to the host and verify the expected setting is configured in the /etc/pam.d/passwd file. The entry format will look similar to "password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok shadow". Edit the file and replace the existing hash key ( md5, des, or sha256) with sha512 or append sha512, if there is no existing key. For example: "password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok shadow sha512".

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54067r798893_chk'
  tag severity: 'medium'
  tag gid: 'V-250632'
  tag rid: 'SV-250632r798895_rule'
  tag stig_id: 'SRG-OS-000120-ESXI5'
  tag gtitle: 'SRG-OS-000120-VMM-000600'
  tag fix_id: 'F-54021r798894_fix'
  tag 'documentable'
  tag legacy: ['SV-51076', 'V-39260']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
