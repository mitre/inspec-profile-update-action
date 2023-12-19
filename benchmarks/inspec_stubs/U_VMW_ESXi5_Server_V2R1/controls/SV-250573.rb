control 'SV-250573' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder. Many computer compromises occur as the result of account name and password guessing. This is generally done by someone with an automated script using repeated logon attempts until the correct account and password pair is guessed. Utilities, such as cracklib, can be used to validate passwords are not dictionary words and meet other criteria during password changes.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and verify the expected settings are configured in the  /etc/pam.d/passwd file. The entry format is :

"password requisite /lib/security/pam_passwdqc.so similar=deny retry=N min=N0,N1,N2,N3,N4"

The "N2" field controls the behavior enforcing "no dictionary words". This flag should be set to "disabled".

# grep "^password" /etc/pam.d/passwd | grep requisite | grep "min="

If the "N2" password complexity field is not set to "disabled", this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the host and ensure the expected settings of the "min" keyword are configured in the  /etc/pam.d/passwd file. 

# vi /etc/pam.d/passwd

Set the "N2" password complexity field to "disabled", i.e., min=disabled,disabled,disabled,disabled,14

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54008r798716_chk'
  tag severity: 'medium'
  tag gid: 'V-250573'
  tag rid: 'SV-250573r798718_rule'
  tag stig_id: 'GEN000790-ESXI5-000085'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53962r798717_fix'
  tag 'documentable'
  tag legacy: ['V-39246', 'SV-51062']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
