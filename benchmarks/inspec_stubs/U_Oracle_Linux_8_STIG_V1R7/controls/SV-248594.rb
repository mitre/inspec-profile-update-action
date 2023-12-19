control 'SV-248594' do
  title 'OL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism. 
 
Examples of attacks are buffer overflow attacks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify that OL 8 implements ASLR with the following command: 
 
$ sudo sysctl kernel.randomize_va_space 
 
kernel.randomize_va_space = 2 
 
If "kernel.randomize_va_space" is not set to "2", this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure OL 8 to implement virtual address space randomization. 
 
Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.d/*.conf" (or modify the line to have the required value): 
 
kernel.randomize_va_space=2 
 
Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Issue the following command to make the changes take effect: 
 
$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52028r858625_chk'
  tag severity: 'medium'
  tag gid: 'V-248594'
  tag rid: 'SV-248594r860918_rule'
  tag stig_id: 'OL08-00-010430'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-51982r858626_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
