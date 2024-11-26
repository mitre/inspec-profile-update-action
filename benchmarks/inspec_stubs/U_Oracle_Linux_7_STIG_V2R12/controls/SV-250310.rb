control 'SV-250310' do
  title 'The Oracle Linux operating system must not allow privileged accounts to utilize SSH.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Note: Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in conjunction with SELinux.

Verify the operating system prevents privileged accounts from utilizing SSH.
Check the SELinux ssh_sysadm_login boolean with the following command:

$ sudo getsebool ssh_sysadm_login
ssh_sysadm_login --> off

If the "ssh_sysadm_login" boolean is not "off" and is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent privileged accounts from utilizing SSH.
Use the following command to set the "ssh_sysadm_login" boolean to "off":

$ sudo setsebool -P ssh_sysadm_login off

Note: SELinux confined users mapped to sysadm_u are not allowed to login to the system over SSH, by default. If this is a required function, it can be configured by setting the ssh_sysadm_login SELinux boolean to "on" with the following command:
$ sudo setsebool -P ssh_sysadm_login on
This must be documented with the ISSO as an operational requirement.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-53744r792813_chk'
  tag severity: 'medium'
  tag gid: 'V-250310'
  tag rid: 'SV-250310r877392_rule'
  tag stig_id: 'OL07-00-020022'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-53698r792814_fix'
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
