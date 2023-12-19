control 'SV-250623' do
  title 'The system must require that passwords contain a minimum of 14 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.
As root, log in to the host and verify the expected settings are configured in the  /etc/pam.d/passwd file. The entry format is :

"password requisite /lib/security/pam_passwdqc.so similar=deny retry=N min=N0,N1,N2,N3,N4"

In addition to other password characteristics, the "N4" field controls the minimum required length of 14 characters.

# grep "^password" /etc/pam.d/passwd | grep requisite | grep "min="

If the "N4" password complexity field is not set to "14" or greater and the "N0" thru "N3" fields are not set to "disabled", this is a finding.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and ensure the expected settings of the "min" keyword are configured in the  /etc/pam.d/passwd file. 

# vi /etc/pam.d/passwd

Set the "N4" password complexity field to "14" or greater and set  the "N0" thru "N3" fields to "disabled", i.e., min=disabled,disabled,disabled,disabled,14

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54058r798866_chk'
  tag severity: 'medium'
  tag gid: 'V-250623'
  tag rid: 'SV-250623r798868_rule'
  tag stig_id: 'SRG-OS-000078-ESXI5'
  tag gtitle: 'SRG-OS-000078-VMM-000450'
  tag fix_id: 'F-54012r798867_fix'
  tag 'documentable'
  tag legacy: ['V-39262', 'SV-51078']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
