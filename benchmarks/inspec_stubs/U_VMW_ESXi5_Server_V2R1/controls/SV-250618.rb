control 'SV-250618' do
  title 'The system must require that passwords contain at least one uppercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.
As root, log in to the host and verify the expected settings are configured in the  /etc/pam.d/passwd file. The entry format is :

"password requisite /lib/security/pam_passwdqc.so similar=deny retry=N min=N0,N1,N2,N3,N4"

The "N4" field controls the behavior requiring at least one character each of the 4 different character classes (i.e., number, special, UPPER_CASE, and lower_case), with a minimum required length of 14 characters.

# grep "^password" /etc/pam.d/passwd | grep requisite | grep "min="

If the "N4" password complexity field is not set to "14" or greater and the "N0" thru "N3" fields are not set to "disabled", this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and ensure the expected settings of the "min" keyword are configured in the  /etc/pam.d/passwd file. 

# vi /etc/pam.d/passwd

Set the "N4" password complexity field to "14" or greater and set  the "N0" thru "N3" fields to "disabled", i.e., min=disabled,disabled,disabled,disabled,14

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54053r798851_chk'
  tag severity: 'medium'
  tag gid: 'V-250618'
  tag rid: 'SV-250618r798853_rule'
  tag stig_id: 'SRG-OS-000069-ESXI5'
  tag gtitle: 'SRG-OS-000069-VMM-000360'
  tag fix_id: 'F-54007r798852_fix'
  tag 'documentable'
  tag legacy: ['SV-51071', 'V-39255']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
