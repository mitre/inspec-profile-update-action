control 'SV-250621' do
  title 'The system must require at least four characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure old and new passwords have significant differences. Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and verify the expected settings are configured in the /etc/pam.d/passwd file. An example line format is:

"password requisite /lib/security/pam_passwdqc.so similar=deny retry=N min=N0,N1,N2,N3,N4" 

# grep "^password" /etc/pam.d/passwd | grep requisite | grep "similar=deny"

If "similar" is not set to "deny", this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and ensure the expected settings of the "min" keyword are configured in the  /etc/pam.d/passwd file. 

# vi /etc/pam.d/passwd

Set the "similar" keyword complexity field to "deny", i.e., similar=deny

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54056r798860_chk'
  tag severity: 'medium'
  tag gid: 'V-250621'
  tag rid: 'SV-250621r798862_rule'
  tag stig_id: 'SRG-OS-000072-ESXI5'
  tag gtitle: 'SRG-OS-000072-VMM-000390'
  tag fix_id: 'F-54010r798861_fix'
  tag 'documentable'
  tag legacy: ['V-39259', 'SV-51075']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
