control 'SV-248590' do
  title 'OL 8 must clear the page allocator to prevent use-after-free attacks.'
  desc 'Adversaries may launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism. 
 
Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.'
  desc 'check', 'Verify that GRUB 2 is configured to enable page poisoning to mitigate use-after-free vulnerabilities with the following commands: 
 
$ sudo grub2-editenv list | grep page_poison 
 
kernelopts=root=/dev/mapper/ol-root ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82 
 
If "page_poison" is not set to "1" or is missing, this is a finding. 
 
Check that page poisoning is enabled by default to persist in kernel updates:  
 
$ sudo grep page_poison /etc/default/grub 
 
GRUB_CMDLINE_LINUX="page_poison=1" 
 
If "page_poison" is not set to "1" or is missing or commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enable page poisoning with the following commands: 
 
$ sudo grubby --update-kernel=ALL --args="page_poison=1" 
 
Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates: 
 
GRUB_CMDLINE_LINUX="page_poison=1"'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52024r779334_chk'
  tag severity: 'medium'
  tag gid: 'V-248590'
  tag rid: 'SV-248590r779336_rule'
  tag stig_id: 'OL08-00-010421'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-51978r779335_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
