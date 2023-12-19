control 'SV-3478' do
  title 'The system is configured to allow installation of printers using kernel-mode drivers.'
  desc 'Kernel-mode drivers are drivers that operate in kernel mode.  Kernel mode allows virtually unlimited access to hardware and memory.  A poorly written kernel driver may cause system instability and data corruption.  Malicious code inserted in a kernel-mode driver has almost no limit on what it may do.  Most modern printers do not require kernel-mode drivers.'
  desc 'fix', 'Configure the system to prevent it from allowing the installation of kernel-mode drivers by setting the policy value for Computer Configuration -> Administrative Templates ->  Printers “Disallow Installation of Printers Using Kernel-mode Drivers” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3478'
  tag rid: 'SV-3478r1_rule'
  tag gtitle: 'Printers - Disallow Installation of Drivers'
  tag fix_id: 'F-5698r1_fix'
  tag 'documentable'
  tag potential_impacts: 'This setting will prevent some applications from installing PDF print drivers.  If necessary temporarily disable this setting while installing a legitimate kernel-mode driver.'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
end
