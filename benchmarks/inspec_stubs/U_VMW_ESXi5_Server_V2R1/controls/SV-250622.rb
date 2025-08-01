control 'SV-250622' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. The entry format will look similar to:

"password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok shadow sha512 remember=5"

As root, log in to the host and execute the following:
# grep "^password" /etc/pam.d/passwd | grep sufficient | grep "remember="

If "remember" is set to less than 5, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. "remember" is an option to pam_unix.so. 
As root, log in to the host and modify the "remember" keyword value, example: "remember=5".
# vi /etc/pam.d/passwd

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54057r798863_chk'
  tag severity: 'medium'
  tag gid: 'V-250622'
  tag rid: 'SV-250622r798865_rule'
  tag stig_id: 'SRG-OS-000077-ESXI5'
  tag gtitle: 'SRG-OS-000077-VMM-000440'
  tag fix_id: 'F-54011r798864_fix'
  tag 'documentable'
  tag legacy: ['SV-51077', 'V-39261']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
